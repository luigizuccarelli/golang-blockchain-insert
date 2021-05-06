package schema

// SchemaInterface - acts as an interface wrapper for our profile schema
// All the go microservices will using this schema
type BlockInterface struct {
	Index     int64  `json:"index"`
	MetaInfo  string `json:"metainfo"`
	ObjectA   string `json:"objecta"`
	ObjectB   string `json:"objectb"`
	ObjectC   string `json:"objectc"`
	Timestamp string `json:"timestamp"`
	Hash      string `json:"hash"`
	PrevHash  string `json:"prevhash"`
}

type InputData struct {
	MetaInfo string `json:"metainfo,omitempty"`
	ObjectA  string `json:"objecta"`
	ObjectB  string `json:"objectb"`
	ObjectC  string `json:"objectc"`
}

// Response schema
type Response struct {
	Name       string `json:"name"`
	StatusCode string `json:"statuscode"`
	Status     string `json:"status"`
	Message    string `json:"message"`
	//BlockChain []BlockInterface `json:"blockchain"`
}
