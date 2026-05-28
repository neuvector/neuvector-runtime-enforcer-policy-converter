package converter

/*
// TODO: consider getting definition from NV.  (IT COULD BE A BIG IMPORT!!)

type NvSecurityProcessProfile struct {
	Baseline *string `json:"baseline"`
	Mode     *string `json:"mode"` // added in 5.4.1 for process/file profiles
}

type NvSecurityProcessRule struct {
	Name            string `json:"name"`
	Path            string `json:"path"`
	Action          string `json:"action"`
	AllowFileUpdate bool   `json:"allow_update"`
}

type NvSecurityTarget struct {
	PolicyMode *string                `json:"policymode,omitempty"`
	Selector   api.RESTCrdGroupConfig `json:"selector"`
}

type NvSecurityRuleSpec struct {
	Target         NvSecurityTarget          `json:"target"`
	ProcessProfile *NvSecurityProcessProfile `json:"process_profile,omitempty"`
	ProcessRule    []NvSecurityProcessRule   `json:"process"`
}

type NvSecurityRule struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec NvSecurityRuleSpec `json:"spec,omitempty"`
}

type NvSecurityRuleList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []NvSecurityRule `json:"items"`
}
*/
