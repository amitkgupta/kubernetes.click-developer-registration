package main

import (
    "bytes"
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/base64"
    "encoding/json"
    "encoding/pem"
    "errors"
    "golang.org/x/net/context"
    "golang.org/x/oauth2"
    "golang.org/x/oauth2/github"
    "io/ioutil"
    "math/big"
    "net/http"
    "os"
    "text/template"
    "time"
)

var (
    githubOauthConfig *oauth2.Config
    oauthStateString string
)

var (
    base64EncodedCACert string
    base64EncodedCAKey string
)

func main() {
    githubOauthConfig = &oauth2.Config{
        RedirectURL:  "https://register.kubernetes.click/github_callback",
        ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
        ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
        Scopes:       []string{"user:email", "read:org"},
        Endpoint:     github.Endpoint,
    }
    oauthStateString = os.Getenv("CSRF_STATE_STRING")

    base64EncodedCACert = os.Getenv("BASE64_ENCODED_CA_CERT")
    base64EncodedCAKey = os.Getenv("BASE64_ENCODED_CA_KEY")

    http.HandleFunc("/", handleIndex)
    http.HandleFunc("/github_callback", handleGithubCallback)
    if err := http.ListenAndServe(":" + os.Getenv("PORT"), nil); err != nil {
        panic(err)
    }
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
    url := githubOauthConfig.AuthCodeURL(oauthStateString)
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleGithubCallback(w http.ResponseWriter, r *http.Request) {
    state := r.FormValue("state")
    if state != oauthStateString {
        println("invalid oauth state, expected " + oauthStateString + ", got " + state)
        http.Error(w, "'state' parameter mismatch from GitHub OAuth callback, someone having a laugh?", http.StatusBadRequest)
        return
    }

    code := r.FormValue("code")
    token, err := githubOauthConfig.Exchange(oauth2.NoContext, code)
    if err != nil {
        println("oauthConf.Exchange() failed with '" + err.Error() + "'")
        http.Error(w, "GitHub OAuth token exchange failed, lost in translation?", http.StatusInternalServerError)
        return
    }
    client := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(token))

    response, err := client.Get("https://api.github.com/user/emails")
    if err != nil {
        println(err.Error())
        http.Error(w, "unable to fetch user's GitHub account emails, eject!", http.StatusInternalServerError)
        return
    }

    defer response.Body.Close()
    contents, err := ioutil.ReadAll(response.Body)
    if err != nil {
        println(err.Error())
        http.Error(w, "unable to read response from GitHub API; this never happens, I swear!", http.StatusInternalServerError)
        return
    }

    emails :=[]struct{
        Email string
        Primary bool
    }{}
    err = json.Unmarshal(contents, &emails)
    if err != nil {
        println(err.Error())
        http.Error(w, "unable to unmarshal emails from GitHub API response, bye bye.", http.StatusInternalServerError)
        return
    }

    var email string
    var allEmails string
    for _, e := range emails {
        allEmails = allEmails + "[" + e.Email + "]"
        if e.Primary {
            email = e.Email
            break
        }
    }
    if email == "" {
        println("unable to find primary email from amongst " + allEmails)
        http.Error(w, "unable to find primary email associated with GitHub account", http.StatusInternalServerError)
        return
    }

    for _, org := range []string{"pivotal-cf", "pivotal-cf-experimental"} {
        response, err = client.Get("https://api.github.com/user/memberships/orgs/" + org)
        if err != nil {
            println(err.Error())
            http.Error(w, "unable to check user's membership in '" + org + "' org, uh oh!", http.StatusInternalServerError)
            return
        }

        if response.StatusCode == http.StatusOK {
            webPage, err := buildWebPage(email)
            if err != nil {
                println(err.Error())
                http.Error(w, "unable to build registration instructions, tell Amit his website is b0rken", http.StatusInternalServerError)
                return
            }

            w.Write([]byte(webPage))
            return
        }
    }

    println("user '" + email + "' is not a member of any valid orgs")
    http.Error(w, "unable to confirm membership in any valid GitHub orgs, who *are* you?", http.StatusUnauthorized)
}

const organization string = "dev"
const caCertField string = "Base64EncodedCACertificate"
const userField string = "User"
const clientCertField string = "Base64EncodedClientCertificate"
const clientKeyField string = "Base64EncodedClientKey"
const kubeConfigTemplateString string =`<!DOCTYPE html><html><body bgcolor="black" style="color: green; white-space: pre-wrap; font-family: monospace; max-width:120ch; word-wrap:break-word;"><font color="grey">## COPY THE CONTENTS INTO ` + "`" + `~/.kube/config'</font>
<font color="lime">$ cat ~/.kube/config</font>
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: {{.` + caCertField + `}}
    server: https://api.kubernetes.click
  name: kubernetes.click
contexts:
- context:
    cluster: kubernetes.click
    namespace: dev
    user: {{.` + userField + `}}
  name: kubernetes.click-dev
current-context: kubernetes.click-dev
kind: Config
preferences: {}
users:
- name: {{.` + userField + `}}
  user:
    client-certificate-data: {{.` + clientCertField + `}}
    client-key-data: {{.` + clientKeyField + `}}

<font color="grey">## RUN A BASIC DEPLOYMENT</font>
<font color="lime">$ kubectl run {{.` + userField + `}}-echo \
  --image=gcr.io/google_containers/echoserver:1.4 \
  --port=8080</font>
deployment "{{.` + userField + `}}-echo" created

<font color="grey">## EXPOSE IT AS A ` + "`" + `NodePort' SERVICE (NOTE: ` + "`" + `LoadBalancer' SERVICES ARE DISABLED)</font>
<font color="lime">$ kubectl expose deployment {{.` + userField + `}}-echo --type=NodePort</font>
service "{{.` + userField + `}}-echo" exposed

<font color="grey">## DETERMINE THE EXPOSED PORT</font>
<font color="lime">$ kubectl get service {{.` + userField + `}}-echo | grep NodePort:</font>
NodePort:               &lt;unset&gt; 300XX/TCP

<font color="grey">## CHECK IT OUT</font>
<font color="lime">$ open http://dev.kubernetes.click:300XX</font></body></html>`

func buildWebPage(user string) (string, error) {
    serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
    serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
    if err != nil {
        return "", err
    }

    reqCert := &x509.Certificate{
        SerialNumber: serialNumber,
        Subject: pkix.Name{
            Organization: []string{organization},
            CommonName: user,
        },
        NotBefore: time.Now(),
        NotAfter: time.Now().Add(365*24*time.Hour),
    }

    caCertPEM, err := base64.StdEncoding.DecodeString(base64EncodedCACert)
    if err != nil {
        return "", err
    }
    block, _ := pem.Decode(caCertPEM)
    if block == nil {
        return "", errors.New("failed to parse certificate")
    }
    caCert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        return "", err
    }

    key, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return "", err
    }

    caKeyPEM, err := base64.StdEncoding.DecodeString(base64EncodedCAKey)
    if err != nil {
        return "", err
    }
    block, _ = pem.Decode(caKeyPEM)
    if block == nil {
        return "", errors.New("failed to parse key")
    }
    caKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        return "", err
    }

    rawCert, err := x509.CreateCertificate(
        rand.Reader,
        reqCert,
        caCert,
        &key.PublicKey,
        caKey,
    )
    if err != nil {
        return "", err
    }

    certBuffer := new(bytes.Buffer)
    err = pem.Encode(certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: rawCert})
    if err != nil {
        return "", err
    }

    keyBuffer := new(bytes.Buffer)
    err = pem.Encode(keyBuffer, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
    if err != nil {
        return "", err
    }

    kubeConfigTemplate, err := template.New("").Parse(kubeConfigTemplateString)
    if err != nil {
        return "", err
    }

    kubeConfigBuffer := new(bytes.Buffer)
    kubeConfigTemplate.Execute(kubeConfigBuffer, map[string]string{
            caCertField: base64EncodedCACert,
            clientKeyField: base64.StdEncoding.EncodeToString(keyBuffer.Bytes()),
            clientCertField: base64.StdEncoding.EncodeToString(certBuffer.Bytes()),
            userField: user,
    })
    return kubeConfigBuffer.String(), nil
}
