package app

import "regexp"

// var base64Regex = regexp.MustCompile(`^(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`)
// var base64Regex = regexp.MustCompile(`^(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)$`)
var base64Regex = regexp.MustCompile(`^([A-Za-z0-9+\/]{4})+([A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$`)

// var wordsRegex = regexp.MustCompile(`\W+`)
var wordsRegex = regexp.MustCompile(`[,:; '"\\]+`)

var defaultExcludePatterns = []string{
	`.*\/(man|docs?|examples?|python[23]\..+|perl5)(\/|$).*`,
	`^\/home(\/|$)`,
	`^\/proc(\/|$)`,
	`^\/sys(\/|$)`,
	`^\/usr\/share(\/|$)`,
	`^\/usr\/lib(\/|$)`,
	`^\/.+(\.pem|\.crt)$`,
}

var defaultPatterns = `
- pattern:
  name: RSA private key
  regex: "-----BEGIN OPENSSH PRIVATE KEY-----"
  confidence: high
- pattern:
  name: RSA private key
  regex: "-----BEGIN RSA PRIVATE KEY-----"
  confidence: high
- pattern:
  name: SSH (DSA) private key
  regex: "-----BEGIN DSA PRIVATE KEY-----"
  confidence: high
- pattern:
  name: SSH (EC) private key
  regex: "-----BEGIN EC PRIVATE KEY-----"
  confidence: high
- pattern:
  name: PGP private key block
  regex: "-----BEGIN PGP PRIVATE KEY BLOCK-----"
  confidence: high
- pattern:
  name: AWS API Key
  regex: "AKIA[0-9A-Z]{16}"
  confidence: high
- pattern:
  name: Amazon MWS Auth Token
  regex: "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
  confidence: high
- pattern:
  name: AWS AppSync GraphQL Key
  regex: "da2-[a-z0-9]{26}"
  confidence: high
- pattern:
  name: GitHub
  regex: '[gG][iI][tT][hH][uU][bB].*[''|"][0-9a-zA-Z]{35,40}[''|"]'
  confidence: high
- pattern:
  name: Generic API Key
  regex: '[aA][pP][iI]_?[kK][eE][yY].*[''|"][0-9a-zA-Z]{32,45}[''|"]'
  confidence: high
- pattern:
  name: Generic Secret
  regex: '[sS][eE][cC][rR][eE][tT].*[''|"][0-9a-zA-Z]{32,45}[''|"]'
  confidence: high
- pattern:
  name: Google API Key
  regex: "AIza[0-9A-Za-z\\-_]{35}"
  confidence: high
- pattern:
  name: Google Cloud Platform API Key
  regex: "AIza[0-9A-Za-z\\-_]{35}"
  confidence: high
- pattern:
  name: Google Cloud Platform OAuth
  regex: "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"
  confidence: high
- pattern:
  name: Google (GCP) Service-account
  regex: '"type": "service_account"'
  confidence: high
- pattern:
  name: Google OAuth Access Token
  regex: "ya29\\.[0-9A-Za-z\\-_]+"
  confidence: high
- pattern:
  name: Password in URL
  regex: "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]"
  confidence: high
`
