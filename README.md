# kubernetes.click-developer-registration

registration application for "[kubernetes.click](https://gist.github.com/amitkgupta/d5ff7dfc691c0e55162f9196b61964d2)" developers

## Usage

```
$ cf login -a api.run.pivotal.io -o <ORG> -s <SPACE>

$ cf push kubernetes.click-developer-registration \
  -b go_buildpack \
  -i 3 \
  -k 32M \
  -m 32M \
  --no-route \
  --no-start

$ cf set-env kubernetes.click-developer-registration \
  GITHUB_CLIENT_ID <GITHUB_CLIENT_ID>
$ cf set-env kubernetes.click-developer-registration \
  GITHUB_CLIENT_SECRET <GITHUB_CLIENT_SECRET>
$ cf set-env kubernetes.click-developer-registration \
  BASE64_ENCODED_CA_CERT <BASE64_ENCODED_CA_CERT>
$ cf set-env kubernetes.click-developer-registration \
  BASE64_ENCODED_CA_KEY <BASE64_ENCODED_CA_KEY>
$ cf set-env kubernetes.click-developer-registration \
  CSRF_STATE_STRING $(uuidgen)

$ cf create-domain <ORG> kubernetes.click
$ cf create-route <SPACE> kubernetes.click \
  --hostname register
$ cf map-route kubernetes.click-developer-registration kubernetes.click \
  --hostname register

$ cf create-route <SPACE> cfapps.io \
  --hostname kubernetesclick-developer-registration
$ cf map-route kubernetes.click-developer-registration cfapps.io \
  --hostname kubernetesclick-developer-registration

$ cf start kubernetes.click-developer-registration
