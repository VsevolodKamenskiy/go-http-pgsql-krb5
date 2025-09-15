package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// ---- Вспомогательные типы под ответ IPA JSON-RPC ----
type ipaRPC struct {
	Method string        `json:"method"`
	Params []interface{} `json:"params"`
}

type ipaResp struct {
	Result struct {
		Result map[string]any `json:"result"`
	} `json:"result"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// ---- Логин в FreeIPA по Kerberos (чистый gokrb5) ----
func loginKerberos(ctx context.Context, ipaBaseURL, krb5ConfPath, ccachePath string) (*http.Client, *http.Cookie, error) {
	u, err := url.Parse(ipaBaseURL)
	if err != nil {
		return nil, nil, fmt.Errorf("ipa url: %w", err)
	}
	host := strings.ToLower(u.Hostname())
	spn := "HTTP/" + host // SPN для HTTP Negotiate

	// 1) Kerberos client из ccache
	cc, err := credentials.LoadCCache(ccachePath)
	if err != nil {
		return nil, nil, fmt.Errorf("load ccache: %w", err)
	}

	krbCfg, err := config.Load(krb5ConfPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load krb5.conf: %w", err)
	}
	cli, err := client.NewFromCCache(cc, krbCfg,
		client.AssumePreAuthentication(true),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("kerb client: %w", err)
	}

	// 2) Получаем сервисный билет для HTTP/<host>
	tkt, skey, err := cli.GetServiceTicket(spn)
	if err != nil {
		return nil, nil, fmt.Errorf("service ticket for %s: %w", spn, err)
	}

	// 3) Собираем KRB5 AP_REQ (GSS-токен Kerberos)
	gtok, err := spnego.NewKRB5TokenAPREQ(
		cli, tkt, skey,
		[]int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf},
		nil,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("build AP_REQ: %w", err)
	}
	rawTok, err := gtok.Marshal()
	if err != nil {
		return nil, nil, fmt.Errorf("marshal AP_REQ: %w", err)
	}
	authz := "Negotiate " + base64.StdEncoding.EncodeToString(rawTok)

	// 4) Делаем login_kerberos с заголовком Authorization
	loginURL := strings.TrimRight(ipaBaseURL, "/") + "/ipa/session/login_kerberos"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, loginURL, nil)
	req.Header.Set("Authorization", authz)
	req.Header.Set("Accept", "application/json") // IPA так любит

	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("login_kerberos: %w", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("login_kerberos HTTP %d", resp.StatusCode)
	}

	// 5) Ищем cookie сессии
	var ipaCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if strings.HasPrefix(c.Name, "ipa_session") {
			ipaCookie = c
			break
		}
	}
	if ipaCookie == nil {
		return nil, nil, errors.New("no ipa_session cookie returned")
	}
	return httpClient, ipaCookie, nil
}

func UserShow(ctx context.Context, ipaBaseURL, krb5ConfPath, ccachePath, uid string) (map[string]any, error) {
	httpClient, cookie, err := loginKerberos(ctx, ipaBaseURL, krb5ConfPath, ccachePath)
	if err != nil {
		return nil, err
	}

	payload := ipaRPC{
		Method: "user_show",
		Params: []any{
			[]string{uid},               // позиционные
			map[string]any{"all": true}, // именованные
		},
	}
	body, _ := json.Marshal(payload)

	jsonURL := strings.TrimRight(ipaBaseURL, "/") + "/ipa/session/json"

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, jsonURL, bytes.NewReader(body))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	base := strings.TrimRight(ipaBaseURL, "/")
	req.Header.Set("Referer", base+"/ipa")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("json rpc: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("json rpc HTTP %d: %s", resp.StatusCode, string(b))
	}

	var out ipaResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if out.Error != nil {
		return nil, fmt.Errorf("ipa error %d: %s", out.Error.Code, out.Error.Message)
	}
	return out.Result.Result, nil
}

func IpaUserHandler(w http.ResponseWriter, r *http.Request) {
	ccacheRaw := r.Header.Get("X_krb5ccname")

	if ccacheRaw == "" {
		log.Println("no delegated credentials")
		http.Error(w, "unauthorized ", http.StatusUnauthorized)
		return
	}

	ccache := strings.Split(ccacheRaw, ":")[1]

	uid := r.URL.Query().Get("uid")
	if uid == "" {
		http.Error(w, "uid is required", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	info, err := UserShow(ctx,
		os.Getenv("FREEIPA_BASE_URL"), // напр. "https://ipa.example.com"
		os.Getenv("KRB5_CONFIG_PATH"),
		ccache,
		uid,
	)

	if err != nil {
		http.Error(w, "ipa: "+err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	err = json.NewEncoder(w).Encode(info)

	if err != nil {
		http.Error(w, "ipa: "+err.Error(), http.StatusInternalServerError)
	}

	w.WriteHeader(http.StatusOK)
	return
}
