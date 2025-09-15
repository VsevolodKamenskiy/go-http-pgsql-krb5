package handlers

import (
	"encoding/json"
	"fmt"
	"github.com/jcmturner/goidentity/v6"
	"go-http-pgsql-krb5/pkg/pgx"
	"net/http"
	"os"
	"strings"
	"time"
)

type dbData struct {
	CurrentUser string    `json:"current_user"`
	SessionUser string    `json:"session_user"`
	Timestamp   time.Time `json:"timestamp"`
}

func TestSelectHandler(w http.ResponseWriter, r *http.Request) {
	ccacheRaw := r.Header.Get("X_krb5ccname")
	if ccacheRaw == "" {
		http.Error(w, "no delegated credentials", http.StatusUnauthorized)
		return
	}
	ccache := strings.Split(ccacheRaw, ":")[1]

	id := goidentity.FromHTTPRequestContext(r)

	if id == nil {
		http.Error(w, "id is required", http.StatusUnauthorized)
	}

	username := id.UserName()
	//domain := id.Domain()

	//principal := fmt.Sprintf("%s@%s", username, strings.ToLower(domain))

	dbDsn := fmt.Sprintf("host=%s user=%s dbname=%s sslmode=require krbsrvname=postgres", os.Getenv("PG_HOST"), username, os.Getenv("PG_DB"))

	rows, err := pgx.QueryAsUser(
		r.Context(),
		dbDsn,
		ccache,
		os.Getenv("KRB5_CONFIG_PATH"), // либо "" чтобы взять системный
		"select current_user, session_user, now()",
	)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	userDataList := make([]dbData, len(rows))

	for _, row := range rows {

		var userdata dbData

		userdata.CurrentUser = row[0].(string)
		userdata.SessionUser = row[1].(string)
		userdata.Timestamp = row[2].(time.Time)

		userDataList = append(userDataList, userdata)
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(userDataList)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

}
