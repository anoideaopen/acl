package template

const DefaultConnection = `---
{{ with $w := . -}}
version: 1.0.0
name: basic-network
client:
  connection:
    timeout:
      orderer: "300"
      peer:
        endorser: "300"
  credentialStore:
    cryptoStore:
      path: /tmp/msp
    path: /tmp/state-store
  logging:
    level: info
  organization: {{ Peer.Organization }}
  peer:
    timeout:
      connection: 60s
      discovery:
        greylistExpiry: 1s
      response: 180s
  tlsCerts:
    client:
      cert:
        path: {{ .PeerUserTLSDir Peer User }}/client.crt
      key:
        path: {{ .PeerUserTLSDir Peer User }}/client.key

channels:{{ range .Channels }}
  {{ . }}:
    peers:{{ range $w.PeersWithChannel . }}
      {{ .ID }}: {}
    {{- end }}
{{- end }}

orderers:{{ range .Orderers }}
  {{ .ID }}:
    url: grpcs://{{ $w.OrdererAddress . "Listen" }}
    tlsCACerts:
      path: {{ $w.OrdererTLSCACert . }}
{{- end }}

organizations:{{ range .Organizations }}
  {{ .Name }}:
    cryptoPath: /tmp/msp
    mspid: {{ .MSPID }}
    {{- if $w.PeersInOrg .Name }}
    peers:{{ range $w.PeersInOrg .Name }}
      - {{ .ID }}
    {{- end }}
    {{- end }}
    {{- if eq .Name Peer.Organization }}
    users:
      backend:
        key:
          path: {{ $w.PeerUserKeyFound Peer User }}
        cert:
          path: {{ $w.PeerUserCert Peer User }}
    {{- end }}
{{- end }}

peers:{{ range .Peers }}
  {{ .ID }}:
    url: grpcs://{{ $w.PeerAddress . "Listen" }}
    tlsCACerts:
      path: {{ $w.PeerTLSCACert . }}
{{- end }}
{{ end }}
`
