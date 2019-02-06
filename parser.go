package bpf

import (
	"github.com/alecthomas/participle"
	"github.com/alecthomas/participle/lexer"
	"github.com/alecthomas/participle/lexer/ebnf"
	"log"
)

// Filter expressions wrapper
type Filter struct {
	Primitives *Expression ` @@ `
}

// Expression consists of one or more Primitives
type Expression struct {
	Primitive *Primitive  ` @@  `
	Op        string      `[ @( "and" | "or" ) `
	Next      *Expression ` @@ ]`
}

// Qualifiers returns a map containing the qualifiers
// of the expression where the key is the qualifier and the
// values are the Id's from the primitive
func (e *Expression) Qualifiers() map[string][]string {
	m := make(map[string][]string)

	for _, q := range e.Primitive.Qualifiers {
		m[q.String()] = append(m[q.String()], e.Primitive.Id)
	}

	next := e.Next
	for next != nil {
		for _, q := range next.Primitive.Qualifiers {
			m[q.String()] = append(m[q.String()], next.Primitive.Id)
		}
		next = next.Next
	}

	return m
}

// Primitive consist of an id (name or number) preceded by one or more qualifiers
type Primitive struct {
	Qualifiers []*Qualifier `@@ { @@ }`
	Id         string       `(@Mac | @Host | @Number)`
}

// Qualifier there are tree types of qualifiers in a BPF
// expression type, dir, proto
type Qualifier struct {
	Type  *Type      `  @@`
	Dir   *Direction `| @@`
	Proto *Protocol  `| @@`
}

func (q *Qualifier) String() string  {
	k := ""
	if q.Type != nil {
		switch *q.Type {
		case QType.Host: k = "host"
		case QType.Net: k = "net"
		case QType.Port: k = "port"
		}
	} else if q.Proto != nil {
		switch *q.Proto {
		case QProtocol.TCP: k = "tcp"
		case QProtocol.UDP: k = "udp"
		}
	} else if q.Dir != nil {
		switch *q.Dir {
		case QDirection.Dst: k =  "dst"
		case QDirection.Src: k =  "src"
		}
	}
	return k
}

// Type kind of thing the id name or number refers to.
// Possible types are host, net , port
type Type struct {
	Host bool `  @ "host"`
	Net  bool `| @ "net"`
	Port bool `| @ "port"`
}

// Direction specify a particular transfer direction to and/or from id.
// Possible directions are src, dst
type Direction struct {
	Src bool `  @ "src"`
	Dst bool `| @ "dst"`
}

// Protocol restricts the match to a particular protocol.
// Possible protos are: ether, tcp and udp. E.g., 'ether src foo' 'tcp port 21'
type Protocol struct {
	TCP	 	bool `  @ "tcp"`
	UDP 	bool `| @ "udp"`
	Ether 	bool `| @ "ether"`
}

type typeList struct {
	Host Type
	Net  Type
	Port Type
}

var QType = &typeList{
	Host: Type{Host: true},
	Net:  Type{Net: true},
	Port: Type{Port: true},
}

type directionList struct {
	Src Direction
	Dst Direction
}

var QDirection = &directionList{
	Src: Direction{Src: true},
	Dst: Direction{Dst: true},
}

type protocolList struct {
	TCP Protocol
	UDP Protocol
	Ether Protocol
}

var QProtocol = &protocolList{
	TCP: Protocol{TCP: true},
	UDP: Protocol{UDP: true},
	Ether: Protocol{Ether: true},
}

// Compare compares the qualifier value
func (q *Qualifier) Compare(t *Qualifier) bool {

	if &q == &t {
		return true
	}

	if q.Type != nil && t.Type != nil && *q.Type != *t.Type {
		return false
	}

	if q.Dir != nil && t.Dir != nil && *q.Dir != *t.Dir {
		return false
	}

	if q.Proto != nil && t.Proto != nil && *q.Proto != *t.Proto {
		return false
	}

	return true
}

var (
	bpfLexer = lexer.Must(ebnf.New(`
Ident = (alpha | "_") { "_" | alpha | digit } .
String = "\"" { "\u0000"…"\uffff"-"\""-"\\" | "\\" any } "\"" .
Number = [ "-" | "+" ] ("." | digit) {"." | digit} .
Punct = "!"…"/" | ":"…"@" | "["…` + "\"`\"" + ` | "{"…"~" .
Whitespace = " " | "\t" | "\n" | "\r" .
Mac = ("af:") .
Host =  (IPv4_1 IPv4_1 IPv4_1 "." IPv4_1) .

IPv4_1 = ([ digit ] | [ digit1_9 ][ digit ] | "1"[ digit ]"1"[ digit ] | "2"["0"…"4"][ digit ] | "25"["0"…"5"]) .
alpha = "a"…"z" | "A"…"Z" .
digit = "0"…"9" .
digit1_9 = "1"…"9" .
mac_1 = "a"…"f" | "A"…"F" | digit .
any = "\u0000"…"\uffff" .
	`))

	bpfParser = participle.MustBuild(
		&Filter{},
		participle.Lexer(bpfLexer),
		participle.Unquote("String"),
		participle.CaseInsensitive("Ident"),
		participle.Elide("Whitespace"),
		// Need to solve left recursion detection first, if possible.
		// participle.UseLookahead(),
	)
)

// Parse receives a BPF expression and returns an Filter object
// from the parsed expression
func Parse(s string) (*Filter, error) {

	result := &Filter{}
	error := bpfParser.ParseString(s, result)

	if error != nil {
		log.Fatal(error)
		return nil, error
	}

	return result, nil
}
