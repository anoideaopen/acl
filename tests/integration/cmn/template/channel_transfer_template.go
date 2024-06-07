package template

const DefaultChannelTransfer = `{{ with $w := . -}}
logLevel: debug
logType: console
profilePath: {{ .ConnectionPath User }}
userName: backend
listenAPI:
  accessToken: {{ .ChannelTransferAccessToken }}
  addressHTTP: {{ .ChannelTransferHTTPAddress }}
  addressGRPC: {{ .ChannelTransferGRPCAddress }}
service:
  address: {{ .ChannelTransferHostAddress }}
options:
  batchTxPreimagePrefix: batchTransactions
  collectorsBufSize: 1
  executeTimeout: 0s
  retryExecuteAttempts: 3
  retryExecuteMaxDelay: 2s
  retryExecuteDelay: 500ms
  ttl: {{ .ChannelTransferTTL }}
  transfersInHandleOnChannel: 50
  newestRequestStreamBufferSize: 50
channels:{{ range .Channels }}
  {{- if ne . "acl" }}
  - {{ . }}
  {{- end }}
{{- end }}
cryptoSrc: local
vaultCryptoSettings:
  useRenewableVaultTokens: false
  userCert: ""
  vaultAddress: http://vault.vault:8200
  vaultAuthPath: /v1/auth/kubernetes/login
  vaultNamespace: atomyze/transfer/
  vaultRole: ""
  vaultServiceTokenPath: null
  vaultToken: ""
googleCryptoSettings:
  gcloudCreds: null
  gcloudProject: null
  userCert: null
redisStorage:
  addr:{{ range .ChannelTransfer.RedisAddresses }}
    - {{ . }}
  {{- end }}
  dbPrefix: transfer
  password: ""
  afterTransferTTL: 3600s	
promMetrics:
  prefix: transfer
{{ end }}
`
