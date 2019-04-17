package crypt

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncrypt(t *testing.T) {

	t.Run("ReturnsEncryptedValueWithNonceDotEncryptedString", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		originalText := "this is my secret"

		// act
		encryptedTextPlusNonce, err := secretHelper.Encrypt(originalText)

		assert.Nil(t, err)
		splittedStrings := strings.Split(encryptedTextPlusNonce, ".")
		assert.Equal(t, 2, len(splittedStrings))
		assert.Equal(t, 16, len(splittedStrings[0]))
		fmt.Println(encryptedTextPlusNonce)
	})
}

func TestEncryptEnvelope(t *testing.T) {

	t.Run("ReturnsEncryptedValueWithNonceDotEncryptedStringInEnvelope", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		originalText := "this is my secret"

		// act
		encryptedTextInEnvelope, err := secretHelper.EncryptEnvelope(originalText)

		assert.Nil(t, err)
		assert.True(t, strings.HasPrefix(encryptedTextInEnvelope, "estafette.secret("))
		assert.True(t, strings.HasSuffix(encryptedTextInEnvelope, ")"))
	})
}

func TestDecrypt(t *testing.T) {

	t.Run("ReturnsOriginalValue", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		originalText := "this is my secret"
		encryptedTextPlusNonce := "deFTz5Bdjg6SUe29.oPIkXbze5G9PNEWS2-ZnArl8BCqHnx4MdTdxHg37th9u"

		// act
		decryptedText, err := secretHelper.Decrypt(encryptedTextPlusNonce)

		assert.Nil(t, err)
		assert.Equal(t, originalText, decryptedText)
	})

	t.Run("ReturnsErrorIfStringDoesNotContainDot", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		encryptedTextPlusNonce := "deFTz5Bdjg6SUe29oPIkXbze5G9PNEWS2-ZnArl8BCqHnx4MdTdxHg37th9u"

		// act
		_, err := secretHelper.Decrypt(encryptedTextPlusNonce)

		assert.NotNil(t, err)
	})
}

func TestDecryptEnvelope(t *testing.T) {

	t.Run("ReturnsOriginalValue", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		originalText := "this is my secret"
		encryptedTextPlusNonce := "estafette.secret(deFTz5Bdjg6SUe29.oPIkXbze5G9PNEWS2-ZnArl8BCqHnx4MdTdxHg37th9u)"

		// act
		decryptedText, err := secretHelper.DecryptEnvelope(encryptedTextPlusNonce)

		assert.Nil(t, err)
		assert.Equal(t, originalText, decryptedText)
	})

	t.Run("ReturnsErrorIfStringDoesNotContainDot", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		encryptedTextPlusNonce := "estafette.secret(deFTz5Bdjg6SUe29oPIkXbze5G9PNEWS2-ZnArl8BCqHnx4MdTdxHg37th9u)"

		// act
		_, err := secretHelper.DecryptEnvelope(encryptedTextPlusNonce)

		assert.NotNil(t, err)
	})

	t.Run("ReturnsOriginalValueIfBuilderConfigHasNoSecrets", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		builderConfigJSON := `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"estafette-ci-builder","app-group":"estafette-ci","language":"golang","team":"estafette-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"master"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/estafette/${ESTAFETTE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ESTAFETTE_BUILD_VERSION} -X main.revision=${ESTAFETTE_GIT_REVISION} -X main.branch=${ESTAFETTE_GIT_BRANCH} -X main.buildDate=${ESTAFETTE_BUILD_DATETIME}\" -o ./publish/${ESTAFETTE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-estafette","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["estafette"]}}],"Releases":null},"jobName":"build-estafette-estafette-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"estafette","repoName":"estafette-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"${ESTAFETTE_GITHUB_API_TOKEN}"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"estafette/estafette-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`

		// act
		decryptedText, err := secretHelper.DecryptEnvelope(builderConfigJSON)

		assert.Nil(t, err)
		assert.Equal(t, builderConfigJSON, decryptedText)
	})
}

func TestDecryptAllEnvelopes(t *testing.T) {

	t.Run("ReturnsOriginalValue", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		builderConfigJSON := `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"estafette-ci-builder","app-group":"estafette-ci","language":"golang","team":"estafette-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"master"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/estafette/${ESTAFETTE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ESTAFETTE_BUILD_VERSION} -X main.revision=${ESTAFETTE_GIT_REVISION} -X main.branch=${ESTAFETTE_GIT_BRANCH} -X main.buildDate=${ESTAFETTE_BUILD_DATETIME}\" -o ./publish/${ESTAFETTE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-estafette","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["estafette"]}}],"Releases":null},"jobName":"build-estafette-estafette-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"estafette","repoName":"estafette-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"estafette.secret(deFTz5Bdjg6SUe29.oPIkXbze5G9PNEWS2-ZnArl8BCqHnx4MdTdxHg37th9u)"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"estafette/estafette-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`
		expectedValue := `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"estafette-ci-builder","app-group":"estafette-ci","language":"golang","team":"estafette-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"master"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/estafette/${ESTAFETTE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ESTAFETTE_BUILD_VERSION} -X main.revision=${ESTAFETTE_GIT_REVISION} -X main.branch=${ESTAFETTE_GIT_BRANCH} -X main.buildDate=${ESTAFETTE_BUILD_DATETIME}\" -o ./publish/${ESTAFETTE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-estafette","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["estafette"]}}],"Releases":null},"jobName":"build-estafette-estafette-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"estafette","repoName":"estafette-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"this is my secret"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"estafette/estafette-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`

		// act
		decryptedText, err := secretHelper.DecryptAllEnvelopes(builderConfigJSON)

		assert.Nil(t, err)
		assert.Equal(t, expectedValue, decryptedText)

	})
}

func TestReencryptAllEnvelopes(t *testing.T) {

	t.Run("ReturnsReencryptedValuesAndNewKey", func(t *testing.T) {

		base64encodedKey := false
		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", base64encodedKey)
		builderConfigJSON := `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"estafette-ci-builder","app-group":"estafette-ci","language":"golang","team":"estafette-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"master"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/estafette/${ESTAFETTE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ESTAFETTE_BUILD_VERSION} -X main.revision=${ESTAFETTE_GIT_REVISION} -X main.branch=${ESTAFETTE_GIT_BRANCH} -X main.buildDate=${ESTAFETTE_BUILD_DATETIME}\" -o ./publish/${ESTAFETTE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-estafette","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["estafette"]}}],"Releases":null},"jobName":"build-estafette-estafette-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"estafette","repoName":"estafette-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"estafette.secret(deFTz5Bdjg6SUe29.oPIkXbze5G9PNEWS2-ZnArl8BCqHnx4MdTdxHg37th9u)"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"estafette/estafette-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`

		// act
		reencryptedText, key, err := secretHelper.ReencryptAllEnvelopes(builderConfigJSON, base64encodedKey)

		assert.Nil(t, err)
		assert.Equal(t, 32, len(key))
		assert.NotEqual(t, builderConfigJSON, reencryptedText)
	})

	t.Run("ReturnsReencryptedValuesAndNewKeyWithBase64EncodedKey", func(t *testing.T) {

		base64encodedKey := true
		secretHelper := NewSecretHelper("U2F6YndNZjNOWnhWVmJCcVFIZWJQY1hDcXJWbjNERHA=", base64encodedKey)
		builderConfigJSON := `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"estafette-ci-builder","app-group":"estafette-ci","language":"golang","team":"estafette-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"master"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/estafette/${ESTAFETTE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ESTAFETTE_BUILD_VERSION} -X main.revision=${ESTAFETTE_GIT_REVISION} -X main.branch=${ESTAFETTE_GIT_BRANCH} -X main.buildDate=${ESTAFETTE_BUILD_DATETIME}\" -o ./publish/${ESTAFETTE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-estafette","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["estafette"]}}],"Releases":null},"jobName":"build-estafette-estafette-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"estafette","repoName":"estafette-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"estafette.secret(deFTz5Bdjg6SUe29.oPIkXbze5G9PNEWS2-ZnArl8BCqHnx4MdTdxHg37th9u)"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"estafette/estafette-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`

		// act
		reencryptedText, key, err := secretHelper.ReencryptAllEnvelopes(builderConfigJSON, base64encodedKey)

		assert.Nil(t, err)
		assert.Equal(t, 44, len(key))
		assert.NotEqual(t, builderConfigJSON, reencryptedText)
	})

	t.Run("ReturnsReencryptedValuesAndNewKeyAndDecryptsThemAfterwards", func(t *testing.T) {

		base64encodedKey := false
		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", base64encodedKey)
		builderConfigJSON := `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"estafette-ci-builder","app-group":"estafette-ci","language":"golang","team":"estafette-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"master"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/estafette/${ESTAFETTE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ESTAFETTE_BUILD_VERSION} -X main.revision=${ESTAFETTE_GIT_REVISION} -X main.branch=${ESTAFETTE_GIT_BRANCH} -X main.buildDate=${ESTAFETTE_BUILD_DATETIME}\" -o ./publish/${ESTAFETTE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-estafette","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["estafette"]}}],"Releases":null},"jobName":"build-estafette-estafette-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"estafette","repoName":"estafette-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"estafette.secret(deFTz5Bdjg6SUe29.oPIkXbze5G9PNEWS2-ZnArl8BCqHnx4MdTdxHg37th9u)"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"estafette/estafette-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`
		expectedValue := `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"estafette-ci-builder","app-group":"estafette-ci","language":"golang","team":"estafette-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"master"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/estafette/${ESTAFETTE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ESTAFETTE_BUILD_VERSION} -X main.revision=${ESTAFETTE_GIT_REVISION} -X main.branch=${ESTAFETTE_GIT_BRANCH} -X main.buildDate=${ESTAFETTE_BUILD_DATETIME}\" -o ./publish/${ESTAFETTE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-estafette","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["estafette"]}}],"Releases":null},"jobName":"build-estafette-estafette-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"estafette","repoName":"estafette-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"this is my secret"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"estafette/estafette-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`

		reencryptedText, key, err := secretHelper.ReencryptAllEnvelopes(builderConfigJSON, base64encodedKey)
		secretHelper = NewSecretHelper(key, base64encodedKey)

		// act
		decryptedText, err := secretHelper.DecryptAllEnvelopes(reencryptedText)

		assert.Nil(t, err)
		assert.Equal(t, expectedValue, decryptedText)
	})

	t.Run("ReturnsReencryptedValuesAndNewKeyAndDecryptsThemAfterwardsWithBase64EncodedKey", func(t *testing.T) {

		base64encodedKey := true
		secretHelper := NewSecretHelper("U2F6YndNZjNOWnhWVmJCcVFIZWJQY1hDcXJWbjNERHA=", base64encodedKey)
		builderConfigJSON := `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"estafette-ci-builder","app-group":"estafette-ci","language":"golang","team":"estafette-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"master"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/estafette/${ESTAFETTE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ESTAFETTE_BUILD_VERSION} -X main.revision=${ESTAFETTE_GIT_REVISION} -X main.branch=${ESTAFETTE_GIT_BRANCH} -X main.buildDate=${ESTAFETTE_BUILD_DATETIME}\" -o ./publish/${ESTAFETTE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-estafette","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["estafette"]}}],"Releases":null},"jobName":"build-estafette-estafette-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"estafette","repoName":"estafette-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"estafette.secret(deFTz5Bdjg6SUe29.oPIkXbze5G9PNEWS2-ZnArl8BCqHnx4MdTdxHg37th9u)"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"estafette/estafette-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`
		expectedValue := `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"estafette-ci-builder","app-group":"estafette-ci","language":"golang","team":"estafette-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"master"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/estafette/${ESTAFETTE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ESTAFETTE_BUILD_VERSION} -X main.revision=${ESTAFETTE_GIT_REVISION} -X main.branch=${ESTAFETTE_GIT_BRANCH} -X main.buildDate=${ESTAFETTE_BUILD_DATETIME}\" -o ./publish/${ESTAFETTE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-estafette","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["estafette"]}}],"Releases":null},"jobName":"build-estafette-estafette-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"estafette","repoName":"estafette-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"this is my secret"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"estafette/estafette-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`

		reencryptedText, key, err := secretHelper.ReencryptAllEnvelopes(builderConfigJSON, base64encodedKey)
		secretHelper = NewSecretHelper(key, base64encodedKey)

		// act
		decryptedText, err := secretHelper.DecryptAllEnvelopes(reencryptedText)

		assert.Nil(t, err)
		assert.Equal(t, expectedValue, decryptedText)
	})
}
