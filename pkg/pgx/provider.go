package pgx

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"net"
	"os"
	"strings"
	"time"
)

// ---- GSS провайдер, построенный на gokrb5 + ccache ----

type gssFromCCache struct {
	cl *client.Client
}

func NewGSSFromCCache(ccachePath, krb5ConfPath string, opts ...func(*client.Settings)) (pgconn.GSS, error) {
	cc, err := credentials.LoadCCache(ccachePath)
	if err != nil {
		return nil, fmt.Errorf("load ccache: %w", err)
	}
	var cfg *config.Config
	if krb5ConfPath != "" {
		cfg, err = config.Load(krb5ConfPath)
		if err != nil {
			return nil, fmt.Errorf("load krb5.conf: %w", err)
		}
	} else {
		cfg = config.New() // допустимо, если krb5.conf системный
	}
	cl, err := client.NewFromCCache(cc, cfg, opts...)
	if err != nil {
		return nil, fmt.Errorf("client from ccache: %w", err)
	}
	return &gssFromCCache{cl: cl}, nil
}

func (g *gssFromCCache) GetInitToken(host, service string) ([]byte, error) {
	spn := service + "/" + canonicalizeHost(host)
	return g.GetInitTokenFromSPN(spn)
}

func (g *gssFromCCache) GetInitTokenFromSPN(spn string) ([]byte, error) {
	// Получаем сервисный тикет и сессионный ключ для SPN
	tkt, key, err := g.cl.GetServiceTicket(spn)
	if err != nil {
		return nil, fmt.Errorf("get service ticket for %s: %w", spn, err)
	}
	// Собираем GSS-микротокен Kerberos (AP_REQ) с обязательными флагами
	krbTok, err := spnego.NewKRB5TokenAPREQ(
		g.cl, tkt, key,
		[]int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf, gssapi.ContextFlagMutual}, // INTEG/CONF обычно достаточно
		nil, // без спец. APOptions
	)
	if err != nil {
		return nil, fmt.Errorf("build KRB5 token: %w", err)
	}
	return krbTok.Marshal()
}

// В Postgres обычно один раунд (AP_REQ). Если сервер пришлёт AP_REP, просто завершаем.
func (g *gssFromCCache) Continue(inToken []byte) (bool, []byte, error) {
	var tok spnego.KRB5Token
	if err := tok.Unmarshal(inToken); err != nil {
		// если пришло что-то нестандартное — считаем обмен завершенным
		return true, nil, nil
	}
	// Нет ответа, либо AP_REP/KRB-ERROR — в обоих случаях новых токенов не шлём
	return true, nil, nil
}

func canonicalizeHost(h string) string {
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	// при желании можно добавить net.LookupCNAME/LookupHost, чтобы получить FQDN
	return h
}

// ---- Как использовать в хэндлере ----

// Рекомендуемый вариант для E2E SSO: открывать ПРОСТОЕ соединение на запрос,
// выполняем нужный SQL и закрываем — без пула (иначе перемешаете креды).
func QueryAsUser(ctx context.Context, dsn string, ccachePath string, krb5Conf string, sql string, args ...any) (rows [][]any, _ error) {
	// Регистрируем фабрику GSS, возвращающую провайдер из нужного ccache.
	// Это глобальная регистрация в pgconn, поэтому создание соединения MUST быть
	// синхронизировано, если у вас параллелизм. Проще — не использовать пул.
	pgconn.RegisterGSSProvider(func() (pgconn.GSS, error) {
		return NewGSSFromCCache(ccachePath, krb5Conf,
			// полезные тюнинги клиента:
			client.AssumePreAuthentication(true),
			client.DisablePAFXFAST(false),
		)
	})

	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	// (опционально) указать TLS, таймауты, Dialer и т.п.
	cfg.ConnectTimeout = 5 * time.Second
	cfg.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: os.Getenv("PG_HOST")}

	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)

	r, err := conn.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	var out [][]any
	for r.Next() {
		vals, err := r.Values()
		if err != nil {
			return nil, err
		}
		out = append(out, vals)
	}
	return out, r.Err()
}

// Если всё же критично использовать pgxpool, делайте ПУЛ НА ЗАПРОС:
//   - MaxConns=1, MinConns=0, MaxConnLifetime ~ время жизни делегированного ccache (или меньше)
//   - создавайте pool в хэндлере, используйте, закрывайте.
//
// Постоянный общий пул НЕподходит для E2E SSO — там смешаются пользователи.
func PoolForUser(ctx context.Context, dsn, ccachePath, krb5Conf string) (*pgxpool.Pool, error) {
	pgconn.RegisterGSSProvider(func() (pgconn.GSS, error) {
		return NewGSSFromCCache(ccachePath, krb5Conf)
	})
	pc, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	pc.MaxConns = 1
	pc.MinConns = 0
	pc.MaxConnLifetime = 30 * time.Second
	pc.HealthCheckPeriod = 0
	pc.ConnConfig.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := net.Dialer{Timeout: 5 * time.Second}
		return d.DialContext(ctx, network, addr)
	}
	return pgxpool.NewWithConfig(ctx, pc)
}
