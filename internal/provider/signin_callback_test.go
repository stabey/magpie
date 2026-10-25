package provider

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCodexPastedCallback(t *testing.T) {
	claudeHome(t)
	var calls atomic.Int32
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		r.ParseForm()
		if r.Form.Get("code") != "pasted-code" || r.Form.Get("code_verifier") == "" || !strings.HasSuffix(r.Form.Get("redirect_uri"), "/auth/callback") {
			t.Error("missing original OAuth exchange parameters")
		}
		json.NewEncoder(w).Encode(map[string]any{
			"id_token":      fakeJWT(map[string]any{"email": "paste@example.com", "https://api.openai.com/auth": map[string]any{"chatgpt_plan_type": "plus", "chatgpt_account_id": "acct-paste"}}),
			"access_token":  fakeJWT(map[string]any{"exp": float64(time.Now().Add(time.Hour).Unix())}),
			"refresh_token": "refresh-paste",
		})
	}))
	defer fake.Close()
	oldTok, oldAddr := codexTokenURL, codexCallbackAddr
	t.Cleanup(func() { codexTokenURL, codexCallbackAddr = oldTok, oldAddr })
	codexTokenURL = fake.URL
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	codexCallbackAddr = ln.Addr().String()
	ln.Close()
	st, err := StartSignIn("codex")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { CancelSignIn(st.ID) })
	if !st.PasteCallback {
		t.Fatal("paste mode not advertised")
	}
	auth, _ := url.Parse(st.URL)
	q := url.Values{"code": {"pasted-code"}, "state": {auth.Query().Get("state")}}
	callback := auth.Query().Get("redirect_uri") + "?" + q.Encode()
	for _, raw := range []string{
		"not a URL",
		strings.Replace(callback, "localhost", "example.com", 1),
		strings.Replace(callback, "/auth/callback", "/other", 1),
		callback + "&state=wrong",
		strings.Replace(callback, auth.Query().Get("state"), "wrong", 1),
		callback + "#fragment",
	} {
		if err := SubmitSignInCallback(st.ID, raw); err == nil {
			t.Errorf("accepted invalid callback %q", raw)
		}
	}
	if current, _ := SignInStatus(st.ID); current.State != "waiting" {
		t.Fatal("invalid paste ended pending login")
	}
	if calls.Load() != 0 {
		t.Fatal("invalid paste reached token endpoint")
	}
	if err := SubmitSignInCallback(st.ID, callback); err != nil {
		t.Fatal(err)
	}
	if err := SubmitSignInCallback(st.ID, callback); err == nil {
		t.Fatal("duplicate paste accepted")
	}
	// A local browser callback racing the paste must not exchange the code twice.
	finishInBrowser(t, st, "pasted-code")
	done := waitDone(t, st.ID)
	if done.State != "done" || done.User != "paste@example.com" {
		t.Fatalf("result: %+v", done)
	}
	if calls.Load() != 1 {
		t.Fatalf("exchanged %d times", calls.Load())
	}
	if _, active := loginUsers(Logins("codex")); active != "paste@example.com" {
		t.Fatal("account not persisted")
	}
	if err := SubmitSignInCallback("missing", callback); err == nil {
		t.Fatal("unknown login accepted")
	}
}

func TestPastedCallbackErrorAndCanceled(t *testing.T) {
	claudeHome(t)
	for _, agent := range []string{"claude", "gemini", "antigravity"} {
		t.Run(agent, func(t *testing.T) {
			st, err := StartSignIn(agent)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { CancelSignIn(st.ID) })
			if !st.PasteCallback {
				t.Fatal("paste mode not advertised")
			}
			auth, _ := url.Parse(st.URL)
			callback := auth.Query().Get("redirect_uri") + "?error=access_denied&state=" + url.QueryEscape(auth.Query().Get("state"))
			if err := SubmitSignInCallback(st.ID, callback); err != nil {
				t.Fatal(err)
			}
			if done := waitDone(t, st.ID); done.State != "failed" || done.Error != "access_denied" {
				t.Fatalf("result: %+v", done)
			}
		})
	}
	st, err := StartSignIn("claude")
	if err != nil {
		t.Fatal(err)
	}
	auth, _ := url.Parse(st.URL)
	CancelSignIn(st.ID)
	if err := SubmitSignInCallback(st.ID, auth.Query().Get("redirect_uri")+"?code=x&state="+auth.Query().Get("state")); err == nil {
		t.Fatal("canceled login accepted callback")
	}
}
