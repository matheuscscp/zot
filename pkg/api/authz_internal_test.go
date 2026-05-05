package api

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	"zotregistry.dev/zot/v2/pkg/cel"
	"zotregistry.dev/zot/v2/pkg/log"
	reqCtx "zotregistry.dev/zot/v2/pkg/requestcontext"
)

// permitted returns just the bool from AccessController.isPermitted; tests
// that don't care about the deny reason use this for assert readability.
func permitted(ac *AccessController, evalReq *evalRequest, pg config.PolicyGroup) bool {
	ok, _ := ac.isPermitted(evalReq, pg)
	return ok
}

func TestPolicyConditions(t *testing.T) {
	t.Parallel()

	pastRFC := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	futureRFC := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)

	makeAC := func(policies []config.Policy, groups config.Groups) *AccessController {
		cfg := &config.AccessControlConfig{
			Repositories: config.Repositories{
				"**": config.PolicyGroup{Policies: policies},
			},
			Groups: groups,
		}
		programs, err := CompileAccessControl(cfg)
		if err != nil {
			t.Fatalf("CompileAccessControl: %v", err)
		}

		return &AccessController{Config: cfg, Log: log.NewLogger("debug", ""), compiled: programs}
	}

	makeER := func(username, repo string, groups []string) *evalRequest {
		uac := reqCtx.NewUserAccessControl()
		uac.SetUsername(username)
		uac.AddGroups(groups)

		return &evalRequest{
			userAc:     uac,
			action:     constants.ReadPermission,
			repository: repo,
		}
	}

	t.Run("user policy without conditions is permitted", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]config.Policy{{
			Users:   []string{"alice"},
			Actions: []string{constants.ReadPermission},
		}}, nil)

		assert.True(t, permitted(ac, makeER("alice", "repo", nil), ac.Config.Repositories["**"]))
	})

	t.Run("user policy with future-time condition is permitted", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]config.Policy{{
			Users:   []string{"alice"},
			Actions: []string{constants.ReadPermission},
			Conditions: []config.Condition{{
				Expression: `timestamp(req.now) < timestamp("` + futureRFC + `")`,
				Message:    "access expired",
			}},
		}}, nil)

		assert.True(t, permitted(ac, makeER("alice", "repo", nil), ac.Config.Repositories["**"]))
	})

	t.Run("user policy with past-time condition is denied", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]config.Policy{{
			Users:   []string{"alice"},
			Actions: []string{constants.ReadPermission},
			Conditions: []config.Condition{{
				Expression: `timestamp(req.now) < timestamp("` + pastRFC + `")`,
				Message:    "access expired",
			}},
		}}, nil)

		assert.False(t, permitted(ac, makeER("alice", "repo", nil), ac.Config.Repositories["**"]))
	})

	t.Run("group policy with failing condition is denied", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]config.Policy{{
			Groups:  []string{"devs"},
			Actions: []string{constants.ReadPermission},
			Conditions: []config.Condition{{
				Expression: `timestamp(req.now) < timestamp("` + pastRFC + `")`,
				Message:    "access expired",
			}},
		}}, config.Groups{"devs": config.Group{Users: []string{"alice"}}})

		assert.False(t, permitted(ac, makeER("alice", "repo", []string{"devs"}),
			ac.Config.Repositories["**"]))
	})

	t.Run("condition can reference repository", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]config.Policy{{
			Users:   []string{"alice"},
			Actions: []string{constants.ReadPermission},
			Conditions: []config.Condition{{
				Expression: `req.repository.startsWith("prod/")`,
				Message:    "only prod/* allowed",
			}},
		}}, nil)

		assert.True(t, permitted(ac, makeER("alice", "prod/api", nil), ac.Config.Repositories["**"]))
		assert.False(t, permitted(ac, makeER("alice", "staging/api", nil), ac.Config.Repositories["**"]))
	})

	t.Run("invalid expression fails CompileAccessControl", func(t *testing.T) {
		t.Parallel()

		cfg := &config.AccessControlConfig{
			Repositories: config.Repositories{
				"**": config.PolicyGroup{Policies: []config.Policy{{
					Users:   []string{"alice"},
					Actions: []string{constants.ReadPermission},
					Conditions: []config.Condition{{
						Expression: `this is not valid CEL`,
						Message:    "broken",
					}},
				}}},
			},
		}
		_, err := CompileAccessControl(cfg)
		assert.Error(t, err)
	})

	t.Run("uncompiled expression denies (defense in depth)", func(t *testing.T) {
		t.Parallel()

		// Build the AccessController without going through CompileAccessControl.
		// At authz time the lookup misses and the policy is treated as not granting.
		ac := &AccessController{
			Config: &config.AccessControlConfig{
				Repositories: config.Repositories{
					"**": config.PolicyGroup{Policies: []config.Policy{{
						Users:   []string{"alice"},
						Actions: []string{constants.ReadPermission},
						Conditions: []config.Condition{{
							// A unique expression unlikely to be cached by other tests.
							Expression: `req.repository == "uncompiled-fixture-only"`,
							Message:    "no compile",
						}},
					}}},
				},
			},
			Log: log.NewLogger("debug", ""),
		}

		assert.False(t, permitted(ac, makeER("alice", "uncompiled-fixture-only", nil),
			ac.Config.Repositories["**"]))
	})

	t.Run("expired entry does not contribute glob patterns", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]config.Policy{{
			Users:   []string{"alice"},
			Actions: []string{constants.ReadPermission},
			Conditions: []config.Condition{{
				Expression: `timestamp(req.now) < timestamp("` + pastRFC + `")`,
				Message:    "access expired",
			}},
		}}, nil)

		patterns := ac.getGlobPatterns(makeER("alice", "", nil))
		assert.False(t, patterns["**"])
	})

	t.Run("non-expired entry contributes glob patterns", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]config.Policy{{
			Users:   []string{"alice"},
			Actions: []string{constants.ReadPermission},
			Conditions: []config.Condition{{
				Expression: `timestamp(req.now) < timestamp("` + futureRFC + `")`,
				Message:    "access expired",
			}},
		}}, nil)

		patterns := ac.getGlobPatterns(makeER("alice", "", nil))
		assert.True(t, patterns["**"])
	})
}

// TestPolicyConditionsRequestFields verifies the full set of req.* fields
// exposed to CEL conditions: HTTP context, TLS, reference parsing, auth
// flags, and OIDC claims passthrough.
func TestPolicyConditionsRequestFields(t *testing.T) {
	t.Parallel()

	uac := reqCtx.NewUserAccessControl()
	uac.SetUsername("alice")
	uac.SetClaims(map[string]any{
		"email":          "alice@example.com",
		"email_verified": true,
		"roles":          []any{"prod-pusher", "dev"},
	})

	httpReq := httptest.NewRequest("PUT", "/v2/prod/api/manifests/v1.2.3", nil)
	httpReq.RemoteAddr = "10.0.0.5:54321"
	httpReq.Header.Set("User-Agent", "docker/24.0.7")
	httpReq.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}

	makeER := func() *evalRequest {
		return &evalRequest{
			httpReq:    httpReq,
			userAc:     uac,
			action:     constants.ReadPermission,
			repository: "prod/api",
			reference:  "v1.2.3",
		}
	}

	cases := []struct {
		name string
		expr string
	}{
		{"method", `req.method == "PUT"`},
		{"userAgent", `req.userAgent.startsWith("docker/")`},
		{"client.ip", `req.client.ip == "10.0.0.5"`},
		{"tls.enabled", `req.tls.enabled`},
		{"tls.version", `req.tls.version == "1.3"`},
		{"reference (tag)", `req.reference == "v1.2.3"`},
		{"referenceType is tag", `req.referenceType == "tag"`},
		{"tag set", `req.tag == "v1.2.3"`},
		{"digest empty for tag", `req.digest == ""`},
		{"auth.anonymous false", `!req.auth.anonymous`},
		{"auth.admin false", `!req.auth.admin`},
		{"claims passthrough", `req.claims.email_verified == true`},
		{"claims list", `"prod-pusher" in req.claims.roles`},
		{"action", `req.action == "read"`},
		{"repository", `req.repository == "prod/api"`},
		{"user.username", `req.user.username == "alice"`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := &config.AccessControlConfig{
				Repositories: config.Repositories{
					"**": config.PolicyGroup{Policies: []config.Policy{{
						Users:   []string{"alice"},
						Actions: []string{constants.ReadPermission},
						Conditions: []config.Condition{{
							Expression: tc.expr,
							Message:    "denied",
						}},
					}}},
				},
			}
			programs, err := CompileAccessControl(cfg)
			if err != nil {
				t.Fatalf("CompileAccessControl: %v", err)
			}

			ac := &AccessController{Config: cfg, Log: log.NewLogger("debug", ""), compiled: programs}

			assert.True(t, permitted(ac, makeER(), ac.Config.Repositories["**"]), tc.expr)
		})
	}
}

func TestPolicyConditionsDigestReference(t *testing.T) {
	t.Parallel()

	digest := "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"

	cfg := &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{Policies: []config.Policy{{
				Users:   []string{"alice"},
				Actions: []string{constants.ReadPermission},
				Conditions: []config.Condition{{
					Expression: `req.referenceType == "digest" && req.digest.startsWith("sha256:")`,
					Message:    "expected digest",
				}},
			}}},
		},
	}
	programs, err := CompileAccessControl(cfg)
	if err != nil {
		t.Fatalf("CompileAccessControl: %v", err)
	}

	ac := &AccessController{Config: cfg, Log: log.NewLogger("debug", ""), compiled: programs}

	uac := reqCtx.NewUserAccessControl()
	uac.SetUsername("alice")

	evalReq := &evalRequest{
		userAc:     uac,
		action:     constants.ReadPermission,
		repository: "prod/api",
		reference:  digest,
	}

	assert.True(t, permitted(ac, evalReq, ac.Config.Repositories["**"]))
}

func TestTLSVersionString(t *testing.T) {
	t.Parallel()

	cases := map[uint16]string{
		tls.VersionTLS10: "1.0",
		tls.VersionTLS11: "1.1",
		tls.VersionTLS12: "1.2",
		tls.VersionTLS13: "1.3",
		0xffff:           "",
	}
	for v, want := range cases {
		if got := tlsVersionString(v); got != want {
			t.Errorf("tlsVersionString(%#x) = %q, want %q", v, got, want)
		}
	}
}

func TestEvalRequestNilSafety(t *testing.T) {
	t.Parallel()

	var nilER *evalRequest
	assert.Equal(t, "", nilER.username())
	assert.Nil(t, nilER.groups())

	emptyER := &evalRequest{}
	assert.Equal(t, "", emptyER.username())
	assert.Nil(t, emptyER.groups())
}

func TestCompileAccessControlNilAndAdminPolicy(t *testing.T) {
	t.Parallel()

	programs, err := CompileAccessControl(nil)
	assert.NoError(t, err)
	assert.Nil(t, programs)

	cfg := &config.AccessControlConfig{
		AdminPolicy: config.Policy{
			Users:   []string{"alice"},
			Actions: []string{constants.ReadPermission},
			Conditions: []config.Condition{{
				Expression: `definitely not valid`,
				Message:    "broken admin",
			}},
		},
	}
	_, err = CompileAccessControl(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "adminPolicy")
}

func TestEvalRequestRemoteAddrWithoutPort(t *testing.T) {
	t.Parallel()

	httpReq := httptest.NewRequest("GET", "/v2/", nil)
	httpReq.RemoteAddr = "no-port-here"

	cfg := &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{Policies: []config.Policy{{
				Users:   []string{"alice"},
				Actions: []string{constants.ReadPermission},
				Conditions: []config.Condition{{
					Expression: `req.client.ip == "no-port-here"`,
					Message:    "bad ip",
				}},
			}}},
		},
	}
	programs, err := CompileAccessControl(cfg)
	if err != nil {
		t.Fatalf("CompileAccessControl: %v", err)
	}

	uac := reqCtx.NewUserAccessControl()
	uac.SetUsername("alice")

	ac := &AccessController{Config: cfg, Log: log.NewLogger("debug", ""), compiled: programs}
	evalReq := &evalRequest{httpReq: httpReq, userAc: uac, action: constants.ReadPermission, repository: "r"}

	assert.True(t, permitted(ac, evalReq, ac.Config.Repositories["**"]))
}

func TestPolicyConditionRuntimeTypeError(t *testing.T) {
	t.Parallel()

	cfg := &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{Policies: []config.Policy{{
				Users:   []string{"alice"},
				Actions: []string{constants.ReadPermission},
				Conditions: []config.Condition{{
					Expression: `req.repository`,
					Message:    "wrong type",
				}},
			}}},
		},
	}
	programs, err := CompileAccessControl(cfg)
	if err != nil {
		t.Fatalf("CompileAccessControl: %v", err)
	}

	uac := reqCtx.NewUserAccessControl()
	uac.SetUsername("alice")

	ac := &AccessController{Config: cfg, Log: log.NewLogger("debug", ""), compiled: programs}
	evalReq := &evalRequest{userAc: uac, action: constants.ReadPermission, repository: "r"}

	assert.False(t, permitted(ac, evalReq, ac.Config.Repositories["**"]))
}

func TestPolicyGroupNonMatchingNoActionOrGroup(t *testing.T) {
	t.Parallel()

	cfg := &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{Policies: []config.Policy{
				{Groups: []string{"devs"}, Actions: []string{constants.CreatePermission}},
				{Groups: []string{"others"}, Actions: []string{constants.ReadPermission}},
			}},
		},
	}
	programs, err := CompileAccessControl(cfg)
	if err != nil {
		t.Fatalf("CompileAccessControl: %v", err)
	}

	uac := reqCtx.NewUserAccessControl()
	uac.SetUsername("alice")
	uac.AddGroups([]string{"devs"})

	ac := &AccessController{Config: cfg, Log: log.NewLogger("debug", ""), compiled: programs}
	evalReq := &evalRequest{userAc: uac, action: constants.ReadPermission, repository: "r"}

	assert.False(t, permitted(ac, evalReq, ac.Config.Repositories["**"]))
}

func TestCompileAccessControlDedupesIdenticalExpressions(t *testing.T) {
	t.Parallel()

	cfg := &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{Policies: []config.Policy{
				{
					Users:   []string{"alice"},
					Actions: []string{constants.ReadPermission},
					Conditions: []config.Condition{
						{Expression: `req.repository == "x"`, Message: "first"},
						{Expression: `req.repository == "x"`, Message: "duplicate"},
					},
				},
			}},
		},
	}
	programs, err := CompileAccessControl(cfg)
	assert.NoError(t, err)
	assert.Len(t, programs, 1)
}

func TestNewAccessControllerNilAccessControl(t *testing.T) {
	t.Parallel()

	logCfg := &config.LogConfig{Level: "debug"}
	ctlr := &Controller{
		Config: &config.Config{
			HTTP: config.HTTPConfig{}, // AccessControl is nil
			Log:  logCfg,
		},
	}
	empty := map[string]*cel.Expression{}
	ctlr.compiledConditions.Store(&empty)

	ac := NewAccessController(ctlr)
	assert.NotNil(t, ac)
	assert.NotNil(t, ac.Config)
	assert.Empty(t, ac.Config.Repositories)
}

func TestControllerLoadNewConfigRecompilesConditions(t *testing.T) {
	t.Parallel()

	htp := NewHTPasswd(log.NewLogger("debug", ""))
	htw, err := NewHTPasswdWatcher(htp, "")
	assert.NoError(t, err)

	original := config.New()
	original.HTTP.AccessControl = &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{Policies: []config.Policy{{
				Users:   []string{"alice"},
				Actions: []string{constants.ReadPermission},
				Conditions: []config.Condition{
					{Expression: `req.repository == "old"`, Message: "old"},
				},
			}}},
		},
	}
	originalPrograms, err := CompileAccessControl(original.HTTP.AccessControl)
	assert.NoError(t, err)

	ctlr := &Controller{
		Config:          original,
		Log:             log.NewLogger("debug", ""),
		HTPasswd:        htp,
		HTPasswdWatcher: htw,
	}
	ctlr.compiledConditions.Store(&originalPrograms)

	newConfig := config.New()
	newConfig.HTTP.AccessControl = &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{Policies: []config.Policy{{
				Users:   []string{"alice"},
				Actions: []string{constants.ReadPermission},
				Conditions: []config.Condition{
					{Expression: `req.repository == "new"`, Message: "new"},
				},
			}}},
		},
	}

	ctlr.LoadNewConfig(newConfig)

	updated := *ctlr.compiledConditions.Load()
	_, hasNew := updated[`req.repository == "new"`]
	assert.True(t, hasNew, "new expression should be compiled after reload")
	_, hasOld := updated[`req.repository == "old"`]
	assert.False(t, hasOld, "old expression should be evicted after reload")
}

// TestPolicyConditionForwardedFor verifies that req.client.forwardedFor
// exposes the X-Forwarded-For chain split into a list, and that conditions
// can express "trust XFF only when the TCP peer is the configured proxy".
func TestPolicyConditionForwardedFor(t *testing.T) {
	t.Parallel()

	cfg := &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{Policies: []config.Policy{{
				Users:   []string{"alice"},
				Actions: []string{constants.ReadPermission},
				Conditions: []config.Condition{{
					Expression: `req.client.ip == "10.0.0.5" && size(req.client.forwardedFor) > 0 && req.client.forwardedFor[0] == "192.0.2.7"`,
					Message:    "must arrive via trusted proxy from 192.0.2.7",
				}},
			}}},
		},
	}
	programs, err := CompileAccessControl(cfg)
	assert.NoError(t, err)

	uac := reqCtx.NewUserAccessControl()
	uac.SetUsername("alice")

	mk := func(remoteAddr, xff string) *evalRequest {
		req := httptest.NewRequest("GET", "/v2/", nil)
		req.RemoteAddr = remoteAddr

		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}

		return &evalRequest{
			httpReq:    req,
			userAc:     uac,
			action:     constants.ReadPermission,
			repository: "r",
		}
	}

	ac := &AccessController{Config: cfg, Log: log.NewLogger("debug", ""), compiled: programs}

	// Through the trusted proxy with the expected client IP at the head of XFF: granted.
	assert.True(t, permitted(ac, mk("10.0.0.5:1234", "192.0.2.7, 10.0.0.5"),
		ac.Config.Repositories["**"]))

	// Same XFF claim but TCP peer is NOT the trusted proxy: denied (XFF is spoofable).
	assert.False(t, permitted(ac, mk("203.0.113.9:1234", "192.0.2.7"),
		ac.Config.Repositories["**"]))

	// Trusted proxy but no XFF header: denied.
	assert.False(t, permitted(ac, mk("10.0.0.5:1234", ""),
		ac.Config.Repositories["**"]))
}

// TestPolicyConditionDenyReasonIsSurfaced verifies that when a condition
// denies, the operator-authored Message bubbles up through isPermitted/can
// so the handler can put it in the 403 response detail.
func TestPolicyConditionDenyReasonIsSurfaced(t *testing.T) {
	t.Parallel()

	cfg := &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{Policies: []config.Policy{{
				Users:   []string{"alice"},
				Actions: []string{constants.ReadPermission},
				Conditions: []config.Condition{{
					Expression: `req.repository.startsWith("prod/")`,
					Message:    "alice may only read prod/*",
				}},
			}}},
		},
	}
	programs, err := CompileAccessControl(cfg)
	assert.NoError(t, err)

	uac := reqCtx.NewUserAccessControl()
	uac.SetUsername("alice")

	ac := &AccessController{Config: cfg, Log: log.NewLogger("debug", ""), compiled: programs}
	evalReq := &evalRequest{userAc: uac, action: constants.ReadPermission, repository: "staging/api"}

	ok, reason := ac.isPermitted(evalReq, ac.Config.Repositories["**"])
	assert.False(t, ok)
	assert.Equal(t, "alice may only read prod/*", reason)
}

// TestSetGlobPatternsOrderIndependence verifies that SetGlobPatterns can be
// called before SetIsAdmin without panicking on a nil internal map. This is a
// regression guard for an earlier ordering hazard between the two setters.
func TestSetGlobPatternsOrderIndependence(t *testing.T) {
	t.Parallel()

	uac := reqCtx.NewUserAccessControl()
	uac.SetGlobPatterns(constants.ReadPermission, map[string]bool{"**": true})
	uac.SetIsAdmin(true)
	assert.True(t, uac.IsAdmin())

	uac2 := reqCtx.NewUserAccessControl()
	uac2.SetIsAdmin(true)
	uac2.SetGlobPatterns(constants.ReadPermission, map[string]bool{"**": true})
	assert.True(t, uac2.IsAdmin())
}

func TestPolicyConditionsAnonymousAndAdminFlags(t *testing.T) {
	t.Parallel()

	mkAC := func(expr string) *AccessController {
		cfg := &config.AccessControlConfig{
			Repositories: config.Repositories{
				"**": config.PolicyGroup{Policies: []config.Policy{{
					Users:      []string{"alice", ""},
					Actions:    []string{constants.ReadPermission},
					Conditions: []config.Condition{{Expression: expr, Message: "denied"}},
				}}},
			},
		}
		programs, err := CompileAccessControl(cfg)
		if err != nil {
			t.Fatalf("CompileAccessControl: %v", err)
		}

		return &AccessController{Config: cfg, Log: log.NewLogger("debug", ""), compiled: programs}
	}

	t.Run("anonymous true when username empty", func(t *testing.T) {
		t.Parallel()

		ac := mkAC(`req.auth.anonymous`)
		uac := reqCtx.NewUserAccessControl()
		evalReq := &evalRequest{userAc: uac, action: constants.ReadPermission, repository: "r"}
		assert.True(t, permitted(ac, evalReq, ac.Config.Repositories["**"]))
	})

	t.Run("admin reflects evalRequest.isAdmin", func(t *testing.T) {
		t.Parallel()

		ac := mkAC(`req.auth.admin`)
		uac := reqCtx.NewUserAccessControl()
		uac.SetUsername("alice")
		evalReq := &evalRequest{userAc: uac, action: constants.ReadPermission, repository: "r", isAdmin: true}
		assert.True(t, permitted(ac, evalReq, ac.Config.Repositories["**"]))
	})
}
