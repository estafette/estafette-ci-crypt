package crypt

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncrypt(t *testing.T) {

	t.Run("ReturnsEncryptedValueWithNonceDotEncryptedStringIfPipelineAllowListIsEmpty", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		originalText := "this is my secret"
		pipelineAllowList := ""

		// act
		encryptedTextPlusNonce, err := secretHelper.Encrypt(originalText, pipelineAllowList)

		assert.Nil(t, err)
		splittedStrings := strings.Split(encryptedTextPlusNonce, ".")
		assert.Equal(t, 2, len(splittedStrings))
		assert.Equal(t, 16, len(splittedStrings[0]))
		// fmt.Println(encryptedTextPlusNonce)
	})

	t.Run("ReturnsEncryptedValueWithNonceDotEncryptedStringIfPipelineAllowListIsDefault", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		originalText := "this is my secret"
		pipelineAllowList := ".*"

		// act
		encryptedTextPlusNonce, err := secretHelper.Encrypt(originalText, pipelineAllowList)

		assert.Nil(t, err)
		splittedStrings := strings.Split(encryptedTextPlusNonce, ".")
		assert.Equal(t, 2, len(splittedStrings))
		assert.Equal(t, 16, len(splittedStrings[0]))
		// fmt.Println(encryptedTextPlusNonce)
	})

	t.Run("ReturnsEncryptedValueWithNonceDotEncryptedStringDotPipelineAllowListIfPipelineAllowListIsNonDefault", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		originalText := "this is my secret"
		pipelineAllowList := "github.com/estafette/estafette-ci-api"

		// act
		encryptedTextPlusNonce, err := secretHelper.Encrypt(originalText, pipelineAllowList)

		assert.Nil(t, err)
		splittedStrings := strings.Split(encryptedTextPlusNonce, ".")
		assert.Equal(t, 3, len(splittedStrings))
		assert.Equal(t, 16, len(splittedStrings[0]))
		// fmt.Println(encryptedTextPlusNonce)
		// assert.Fail(t, "show me the encrypted value")
	})
}

func TestEncryptEnvelope(t *testing.T) {

	t.Run("ReturnsEncryptedValueWithNonceDotEncryptedStringInEnvelope", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		originalText := "this is my secret"
		pipelineAllowList := ""

		// act
		encryptedTextInEnvelope, err := secretHelper.EncryptEnvelope(originalText, pipelineAllowList)

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
		pipeline := "github.com/estafette/estafette-ci-api"

		// act
		decryptedText, _, err := secretHelper.Decrypt(encryptedTextPlusNonce, pipeline)

		assert.Nil(t, err)
		assert.Equal(t, originalText, decryptedText)
	})

	t.Run("ReturnsDefaultPipelineWhiteListIfStringContainsOneDot", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		encryptedTextPlusNonce := "deFTz5Bdjg6SUe29.oPIkXbze5G9PNEWS2-ZnArl8BCqHnx4MdTdxHg37th9u"
		pipeline := "github.com/estafette/estafette-ci-api"

		// act
		_, pipelineAllowList, err := secretHelper.Decrypt(encryptedTextPlusNonce, pipeline)

		assert.Nil(t, err)
		assert.Equal(t, ".*", pipelineAllowList)
	})

	t.Run("ReturnsErrorIfStringDoesNotContainDot", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		encryptedTextPlusNonce := "deFTz5Bdjg6SUe29oPIkXbze5G9PNEWS2-ZnArl8BCqHnx4MdTdxHg37th9u"
		pipeline := "github.com/estafette/estafette-ci-api"

		// act
		_, _, err := secretHelper.Decrypt(encryptedTextPlusNonce, pipeline)

		assert.NotNil(t, err)
	})

	t.Run("ReturnsErrorIfStringContainsMoreThan2Dots", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		encryptedTextPlusNonce := "deFTz5Bdjg6SUe29.oPIkXbze5G9PNEWS2-ZnArl8BCqHnx4MdTd.xHg3.7th9u"
		pipeline := "github.com/estafette/estafette-ci-api"

		// act
		_, _, err := secretHelper.Decrypt(encryptedTextPlusNonce, pipeline)

		assert.NotNil(t, err)
	})

	t.Run("ReturnsDecryptedPipelineWhiteListIfStringContainsTwoDots", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		originalText := "this is my secret"
		encryptedTextPlusNonce := "7pB-Znp16my5l-Gz.l--UakUaK5N8KYFt-sVNUaOY5uobSpWabJNVXYDEyDWT.hO6JcRARdtB-PY577NJeUrKMVOx-sjg617wTd8IkAh-PvIm9exuATeDeFiYaEr9eQtfreBQ="
		pipeline := "github.com/estafette/estafette-ci-api"

		// act
		decryptedText, pipelineAllowList, err := secretHelper.Decrypt(encryptedTextPlusNonce, pipeline)

		assert.Nil(t, err)
		assert.Equal(t, originalText, decryptedText)
		assert.Equal(t, "github.com/estafette/estafette-ci-api", pipelineAllowList)
	})

	t.Run("ReturnsDecryptedPipelineWhiteListIfStringContainsTwoDotsAndPipelineMatchesRegex", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		originalText := "this is my secret"
		encryptedTextPlusNonce := "7MZbwVlQJtfLN50U.7dpzK2K9ZYiXw-uy4-VtDQYtUOC8dXGJzvNWBtKNT4SZ._ttuMDe2OMuV1-Sk9fJ-DheE5385dJCn0LQgclmqQWz262VO3kxi"
		pipeline := "github.com/estafette/estafette-ci-web"

		// act
		decryptedText, pipelineAllowList, err := secretHelper.Decrypt(encryptedTextPlusNonce, pipeline)

		assert.Nil(t, err)
		assert.Equal(t, originalText, decryptedText)
		assert.Equal(t, "github.com/estafette/.+", pipelineAllowList)
	})

	t.Run("ReturnsErrorIfPipelineDoesNotMatchPipelineAllowListRegex", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		encryptedTextPlusNonce := "7pB-Znp16my5l-Gz.l--UakUaK5N8KYFt-sVNUaOY5uobSpWabJNVXYDEyDWT.hO6JcRARdtB-PY577NJeUrKMVOx-sjg617wTd8IkAh-PvIm9exuATeDeFiYaEr9eQtfreBQ="
		pipeline := "github.com/estafette/estafette-ci-web"

		// act
		_, _, err := secretHelper.Decrypt(encryptedTextPlusNonce, pipeline)

		assert.NotNil(t, err)
	})
}

func TestDecryptEnvelope(t *testing.T) {

	t.Run("ReturnsOriginalValue", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		originalText := "this is my secret"
		encryptedTextPlusNonce := "estafette.secret(deFTz5Bdjg6SUe29.oPIkXbze5G9PNEWS2-ZnArl8BCqHnx4MdTdxHg37th9u)"
		pipeline := "github.com/estafette/estafette-ci-api"

		// act
		decryptedText, _, err := secretHelper.DecryptEnvelope(encryptedTextPlusNonce, pipeline)

		assert.Nil(t, err)
		assert.Equal(t, originalText, decryptedText)
	})

	t.Run("ReturnsErrorIfStringDoesNotContainDot", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		encryptedTextPlusNonce := "estafette.secret(deFTz5Bdjg6SUe29oPIkXbze5G9PNEWS2-ZnArl8BCqHnx4MdTdxHg37th9u)"
		pipeline := "github.com/estafette/estafette-ci-api"

		// act
		_, _, err := secretHelper.DecryptEnvelope(encryptedTextPlusNonce, pipeline)

		assert.NotNil(t, err)
	})

	t.Run("ReturnsOriginalValueIfBuilderConfigHasNoSecrets", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		builderConfigJSON := `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"estafette-ci-builder","app-group":"estafette-ci","language":"golang","team":"estafette-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"master"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/estafette/${ESTAFETTE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ESTAFETTE_BUILD_VERSION} -X main.revision=${ESTAFETTE_GIT_REVISION} -X main.branch=${ESTAFETTE_GIT_BRANCH} -X main.buildDate=${ESTAFETTE_BUILD_DATETIME}\" -o ./publish/${ESTAFETTE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-estafette","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["estafette"]}}],"Releases":null},"jobName":"build-estafette-estafette-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"estafette","repoName":"estafette-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"${ESTAFETTE_GITHUB_API_TOKEN}"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"estafette/estafette-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`
		pipeline := "github.com/estafette/estafette-ci-api"

		// act
		decryptedText, _, err := secretHelper.DecryptEnvelope(builderConfigJSON, pipeline)

		assert.Nil(t, err)
		assert.Equal(t, builderConfigJSON, decryptedText)
	})
}

func TestDecryptAllEnvelopes(t *testing.T) {

	t.Run("ReturnsOriginalValue", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		builderConfigJSON := `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"estafette-ci-builder","app-group":"estafette-ci","language":"golang","team":"estafette-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"master"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/estafette/${ESTAFETTE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ESTAFETTE_BUILD_VERSION} -X main.revision=${ESTAFETTE_GIT_REVISION} -X main.branch=${ESTAFETTE_GIT_BRANCH} -X main.buildDate=${ESTAFETTE_BUILD_DATETIME}\" -o ./publish/${ESTAFETTE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-estafette","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["estafette"]}}],"Releases":null},"jobName":"build-estafette-estafette-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"estafette","repoName":"estafette-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"estafette.secret(deFTz5Bdjg6SUe29.oPIkXbze5G9PNEWS2-ZnArl8BCqHnx4MdTdxHg37th9u)"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"estafette/estafette-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`
		expectedValue := `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"estafette-ci-builder","app-group":"estafette-ci","language":"golang","team":"estafette-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"master"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/estafette/${ESTAFETTE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ESTAFETTE_BUILD_VERSION} -X main.revision=${ESTAFETTE_GIT_REVISION} -X main.branch=${ESTAFETTE_GIT_BRANCH} -X main.buildDate=${ESTAFETTE_BUILD_DATETIME}\" -o ./publish/${ESTAFETTE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-estafette","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["estafette"]}}],"Releases":null},"jobName":"build-estafette-estafette-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"estafette","repoName":"estafette-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"this is my secret"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"estafette/estafette-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`
		pipeline := "github.com/estafette/estafette-ci-api"

		// act
		decryptedText, err := secretHelper.DecryptAllEnvelopes(builderConfigJSON, pipeline)

		assert.Nil(t, err)
		assert.Equal(t, expectedValue, decryptedText)

	})
}

func TestReencryptAllEnvelopes(t *testing.T) {

	t.Run("ReturnsReencryptedValuesAndNewKey", func(t *testing.T) {

		base64encodedKey := false
		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", base64encodedKey)
		builderConfigJSON := `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"estafette-ci-builder","app-group":"estafette-ci","language":"golang","team":"estafette-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"master"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/estafette/${ESTAFETTE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ESTAFETTE_BUILD_VERSION} -X main.revision=${ESTAFETTE_GIT_REVISION} -X main.branch=${ESTAFETTE_GIT_BRANCH} -X main.buildDate=${ESTAFETTE_BUILD_DATETIME}\" -o ./publish/${ESTAFETTE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-estafette","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["estafette"]}}],"Releases":null},"jobName":"build-estafette-estafette-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"estafette","repoName":"estafette-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"estafette.secret(deFTz5Bdjg6SUe29.oPIkXbze5G9PNEWS2-ZnArl8BCqHnx4MdTdxHg37th9u)"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"estafette/estafette-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`
		pipeline := "github.com/estafette/estafette-ci-api"

		// act
		reencryptedText, key, err := secretHelper.ReencryptAllEnvelopes(builderConfigJSON, pipeline, base64encodedKey)

		assert.Nil(t, err)
		assert.Equal(t, 32, len(key))
		assert.NotEqual(t, builderConfigJSON, reencryptedText)
	})

	t.Run("ReturnsReencryptedValuesAndNewKeyEvenForPipelineRestrictedSecretsForOtherPipelines", func(t *testing.T) {

		base64encodedKey := false
		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", base64encodedKey)
		// the secret in here is restricted to github.com/estafette/estafette-ci-api
		builderConfigJSON := `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"estafette-ci-builder","app-group":"estafette-ci","language":"golang","team":"estafette-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"master"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/estafette/${ESTAFETTE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ESTAFETTE_BUILD_VERSION} -X main.revision=${ESTAFETTE_GIT_REVISION} -X main.branch=${ESTAFETTE_GIT_BRANCH} -X main.buildDate=${ESTAFETTE_BUILD_DATETIME}\" -o ./publish/${ESTAFETTE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-estafette","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["estafette"]}}],"Releases":null},"jobName":"build-estafette-estafette-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"estafette","repoName":"estafette-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"estafette.secret(7pB-Znp16my5l-Gz.l--UakUaK5N8KYFt-sVNUaOY5uobSpWabJNVXYDEyDWT.hO6JcRARdtB-PY577NJeUrKMVOx-sjg617wTd8IkAh-PvIm9exuATeDeFiYaEr9eQtfreBQ=)"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"estafette/estafette-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`
		pipeline := "github.com/estafette/estafette-ci-web"

		// act
		reencryptedText, key, err := secretHelper.ReencryptAllEnvelopes(builderConfigJSON, pipeline, base64encodedKey)

		assert.Nil(t, err)
		assert.Equal(t, 32, len(key))
		assert.NotEqual(t, builderConfigJSON, reencryptedText)

		secretHelper = NewSecretHelper(key, base64encodedKey)
		decryptedText, err := secretHelper.DecryptAllEnvelopes(reencryptedText, "github.com/estafette/estafette-ci-api")
		assert.Nil(t, err)
		assert.Equal(t, `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"estafette-ci-builder","app-group":"estafette-ci","language":"golang","team":"estafette-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"master"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/estafette/${ESTAFETTE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ESTAFETTE_BUILD_VERSION} -X main.revision=${ESTAFETTE_GIT_REVISION} -X main.branch=${ESTAFETTE_GIT_BRANCH} -X main.buildDate=${ESTAFETTE_BUILD_DATETIME}\" -o ./publish/${ESTAFETTE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-estafette","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["estafette"]}}],"Releases":null},"jobName":"build-estafette-estafette-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"estafette","repoName":"estafette-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"this is my secret"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"estafette/estafette-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`, decryptedText)

		_, err = secretHelper.DecryptAllEnvelopes(reencryptedText, pipeline)
		assert.NotNil(t, err)
	})

	t.Run("ReturnsReencryptedValuesAndNewKeyWithBase64EncodedKey", func(t *testing.T) {

		base64encodedKey := true
		secretHelper := NewSecretHelper("U2F6YndNZjNOWnhWVmJCcVFIZWJQY1hDcXJWbjNERHA=", base64encodedKey)
		builderConfigJSON := `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"estafette-ci-builder","app-group":"estafette-ci","language":"golang","team":"estafette-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"master"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/estafette/${ESTAFETTE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ESTAFETTE_BUILD_VERSION} -X main.revision=${ESTAFETTE_GIT_REVISION} -X main.branch=${ESTAFETTE_GIT_BRANCH} -X main.buildDate=${ESTAFETTE_BUILD_DATETIME}\" -o ./publish/${ESTAFETTE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-estafette","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["estafette"]}}],"Releases":null},"jobName":"build-estafette-estafette-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"estafette","repoName":"estafette-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"estafette.secret(deFTz5Bdjg6SUe29.oPIkXbze5G9PNEWS2-ZnArl8BCqHnx4MdTdxHg37th9u)"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"estafette/estafette-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`
		pipeline := "github.com/estafette/estafette-ci-api"

		// act
		reencryptedText, key, err := secretHelper.ReencryptAllEnvelopes(builderConfigJSON, pipeline, base64encodedKey)

		assert.Nil(t, err)
		assert.Equal(t, 44, len(key))
		assert.NotEqual(t, builderConfigJSON, reencryptedText)
	})

	t.Run("ReturnsReencryptedValuesAndNewKeyAndDecryptsThemAfterwards", func(t *testing.T) {

		base64encodedKey := false
		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", base64encodedKey)
		builderConfigJSON := `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"estafette-ci-builder","app-group":"estafette-ci","language":"golang","team":"estafette-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"master"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/estafette/${ESTAFETTE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ESTAFETTE_BUILD_VERSION} -X main.revision=${ESTAFETTE_GIT_REVISION} -X main.branch=${ESTAFETTE_GIT_BRANCH} -X main.buildDate=${ESTAFETTE_BUILD_DATETIME}\" -o ./publish/${ESTAFETTE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-estafette","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["estafette"]}}],"Releases":null},"jobName":"build-estafette-estafette-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"estafette","repoName":"estafette-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"estafette.secret(deFTz5Bdjg6SUe29.oPIkXbze5G9PNEWS2-ZnArl8BCqHnx4MdTdxHg37th9u)"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"estafette/estafette-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`
		expectedValue := `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"estafette-ci-builder","app-group":"estafette-ci","language":"golang","team":"estafette-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"master"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/estafette/${ESTAFETTE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ESTAFETTE_BUILD_VERSION} -X main.revision=${ESTAFETTE_GIT_REVISION} -X main.branch=${ESTAFETTE_GIT_BRANCH} -X main.buildDate=${ESTAFETTE_BUILD_DATETIME}\" -o ./publish/${ESTAFETTE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-estafette","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["estafette"]}}],"Releases":null},"jobName":"build-estafette-estafette-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"estafette","repoName":"estafette-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"this is my secret"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"estafette/estafette-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`
		pipeline := "github.com/estafette/estafette-ci-api"

		reencryptedText, key, err := secretHelper.ReencryptAllEnvelopes(builderConfigJSON, pipeline, base64encodedKey)
		secretHelper = NewSecretHelper(key, base64encodedKey)

		// act
		decryptedText, err := secretHelper.DecryptAllEnvelopes(reencryptedText, pipeline)

		assert.Nil(t, err)
		assert.Equal(t, expectedValue, decryptedText)
	})

	t.Run("ReturnsReencryptedValuesAndNewKeyAndDecryptsThemAfterwardsWithBase64EncodedKey", func(t *testing.T) {

		base64encodedKey := true
		secretHelper := NewSecretHelper("U2F6YndNZjNOWnhWVmJCcVFIZWJQY1hDcXJWbjNERHA=", base64encodedKey)
		builderConfigJSON := `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"estafette-ci-builder","app-group":"estafette-ci","language":"golang","team":"estafette-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"master"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/estafette/${ESTAFETTE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ESTAFETTE_BUILD_VERSION} -X main.revision=${ESTAFETTE_GIT_REVISION} -X main.branch=${ESTAFETTE_GIT_BRANCH} -X main.buildDate=${ESTAFETTE_BUILD_DATETIME}\" -o ./publish/${ESTAFETTE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-estafette","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["estafette"]}}],"Releases":null},"jobName":"build-estafette-estafette-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"estafette","repoName":"estafette-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"estafette.secret(deFTz5Bdjg6SUe29.oPIkXbze5G9PNEWS2-ZnArl8BCqHnx4MdTdxHg37th9u)"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"estafette/estafette-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`
		expectedValue := `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"estafette-ci-builder","app-group":"estafette-ci","language":"golang","team":"estafette-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"master"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/estafette/${ESTAFETTE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ESTAFETTE_BUILD_VERSION} -X main.revision=${ESTAFETTE_GIT_REVISION} -X main.branch=${ESTAFETTE_GIT_BRANCH} -X main.buildDate=${ESTAFETTE_BUILD_DATETIME}\" -o ./publish/${ESTAFETTE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-estafette","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/estafette-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["estafette"]}}],"Releases":null},"jobName":"build-estafette-estafette-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"estafette","repoName":"estafette-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"this is my secret"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"estafette/estafette-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`
		pipeline := "github.com/estafette/estafette-ci-api"

		reencryptedText, key, err := secretHelper.ReencryptAllEnvelopes(builderConfigJSON, pipeline, base64encodedKey)
		secretHelper = NewSecretHelper(key, base64encodedKey)

		// act
		decryptedText, err := secretHelper.DecryptAllEnvelopes(reencryptedText, pipeline)

		assert.Nil(t, err)
		assert.Equal(t, expectedValue, decryptedText)
	})
}

func TestGetAllSecretEnvelopes(t *testing.T) {

	t.Run("ReturnsAllEnvelopes", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)

		input := `
		estafette.secret(deFTz5Bdjg6SUe29.oPIkXbze5G9PNEWS2-ZnArl8BCqHnx4MdTdxHg37th9u)

		estafette.secret(7pB-Znp16my5l-Gz.l--UakUaK5N8KYFt-sVNUaOY5uobSpWabJNVXYDEyDWT.hO6JcRARdtB-PY577NJeUrKMVOx-sjg617wTd8IkAh-PvIm9exuATeDeFiYaEr9eQtfreBQ=)
		`

		// act
		envelopes, err := secretHelper.GetAllSecretEnvelopes(input)

		assert.Nil(t, err)
		if !assert.Equal(t, 2, len(envelopes)) {
			return
		}
		assert.Equal(t, "estafette.secret(deFTz5Bdjg6SUe29.oPIkXbze5G9PNEWS2-ZnArl8BCqHnx4MdTdxHg37th9u)", envelopes[0])
		assert.Equal(t, "estafette.secret(7pB-Znp16my5l-Gz.l--UakUaK5N8KYFt-sVNUaOY5uobSpWabJNVXYDEyDWT.hO6JcRARdtB-PY577NJeUrKMVOx-sjg617wTd8IkAh-PvIm9exuATeDeFiYaEr9eQtfreBQ=)", envelopes[1])
	})
}

func TestGetAllSecrets(t *testing.T) {

	t.Run("ReturnsAllEnvelopeContents", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)

		input := `
		estafette.secret(deFTz5Bdjg6SUe29.oPIkXbze5G9PNEWS2-ZnArl8BCqHnx4MdTdxHg37th9u)

		estafette.secret(7pB-Znp16my5l-Gz.l--UakUaK5N8KYFt-sVNUaOY5uobSpWabJNVXYDEyDWT.hO6JcRARdtB-PY577NJeUrKMVOx-sjg617wTd8IkAh-PvIm9exuATeDeFiYaEr9eQtfreBQ=)
		`

		// act
		secrets, err := secretHelper.GetAllSecrets(input)

		assert.Nil(t, err)
		if !assert.Equal(t, 2, len(secrets)) {
			return
		}
		assert.Equal(t, "deFTz5Bdjg6SUe29.oPIkXbze5G9PNEWS2-ZnArl8BCqHnx4MdTdxHg37th9u", secrets[0])
		assert.Equal(t, "7pB-Znp16my5l-Gz.l--UakUaK5N8KYFt-sVNUaOY5uobSpWabJNVXYDEyDWT.hO6JcRARdtB-PY577NJeUrKMVOx-sjg617wTd8IkAh-PvIm9exuATeDeFiYaEr9eQtfreBQ=", secrets[1])
	})
}

func TestGetAllSecretValues(t *testing.T) {

	t.Run("ReturnsAllDecryptedSecretValues", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)

		input := `
		estafette.secret(deFTz5Bdjg6SUe29.oPIkXbze5G9PNEWS2-ZnArl8BCqHnx4MdTdxHg37th9u)

		estafette.secret(7pB-Znp16my5l-Gz.l--UakUaK5N8KYFt-sVNUaOY5uobSpWabJNVXYDEyDWT.hO6JcRARdtB-PY577NJeUrKMVOx-sjg617wTd8IkAh-PvIm9exuATeDeFiYaEr9eQtfreBQ=)
		`
		pipeline := "github.com/estafette/estafette-ci-api"

		// act
		values, err := secretHelper.GetAllSecretValues(input, pipeline)

		assert.Nil(t, err)
		if !assert.Equal(t, 2, len(values)) {
			return
		}
		assert.Equal(t, "this is my secret", values[0])
		assert.Equal(t, "this is my secret", values[1])
	})

	t.Run("ReturnsErrorIfAnySecretIsNotAllowedForPipeline", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)

		input := `
		estafette.secret(deFTz5Bdjg6SUe29.oPIkXbze5G9PNEWS2-ZnArl8BCqHnx4MdTdxHg37th9u)

		estafette.secret(7pB-Znp16my5l-Gz.l--UakUaK5N8KYFt-sVNUaOY5uobSpWabJNVXYDEyDWT.hO6JcRARdtB-PY577NJeUrKMVOx-sjg617wTd8IkAh-PvIm9exuATeDeFiYaEr9eQtfreBQ=)
		`
		pipeline := "github.com/estafette/estafette-ci-web"

		// act
		values, err := secretHelper.GetAllSecretValues(input, pipeline)

		assert.NotNil(t, err)
		assert.Equal(t, 0, len(values))
	})
}
