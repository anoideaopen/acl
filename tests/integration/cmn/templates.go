package cmn

import (
	"github.com/anoideaopen/acl/tests/integration/cmn/template"
	"github.com/hyperledger/fabric/integration/nwo"
)

// TemplatesFound can be used to provide custom templates to GenerateConfigTree.
type TemplatesFound struct {
	*nwo.Templates
	Robot           string `yaml:"robot,omitempty"`
	Connection      string `yaml:"connection,omitempty"`
	ChannelTransfer string `yaml:"channel_transfer,omitempty"`
}

func (t *TemplatesFound) RobotTemplate() string {
	if t.Robot != "" {
		return t.Robot
	}
	return template.DefaultRobot
}

func (t *TemplatesFound) ConnectionTemplate() string {
	if t.Connection != "" {
		return t.Connection
	}
	return template.DefaultConnection
}

func (t *TemplatesFound) ChannelTransferTemplate() string {
	if t.ChannelTransfer != "" {
		return t.ChannelTransfer
	}
	return template.DefaultChannelTransfer
}
