package bpf_test

import (
	"github.com/letitbeat/bpf-parser"
	"testing"
)

type Output struct {
	Qualifier *bpf.Qualifier
	Id        string
}

func TestParseScalar(t *testing.T) {

	tests := []struct {
		input  string
		output Output
	}{
		{"host 192.168.1.10", Output{&bpf.Qualifier{Type: &bpf.QType.Host}, "192.168.1.10"}},
		{"port 80", Output{&bpf.Qualifier{Type: &bpf.QType.Port}, "80"}},
		{"src 10.10.0.1", Output{&bpf.Qualifier{Dir: &bpf.QDirection.Src}, "10.10.0.1"}},
		{"dst 10.10.0.10", Output{&bpf.Qualifier{Dir: &bpf.QDirection.Dst}, "10.10.0.10"}},
		{"net 10.10", Output{&bpf.Qualifier{Type: &bpf.QType.Net}, "10.10"}},
		{"tcp 80", Output{&bpf.Qualifier{Proto: &bpf.QProtocol.TCP}, "80"}},
		{"udp 44", Output{&bpf.Qualifier{Proto: &bpf.QProtocol.UDP}, "44"}},
		//{"ether af:", Output{&bpf.Qualifier{Proto: &bpf.QProtocol.Ether}, "af"}},
	}

	for _, test := range tests {

		f, err := bpf.Parse(test.input)

		if err != nil {
			t.Errorf("Error parsing: %v", test.input)
		}
		t.Logf("%+v", f.Primitives.Primitive)
		t.Logf("%+v", f.Primitives.Primitive.Qualifiers[0])

		if f.Primitives.Primitive.Id != test.output.Id ||
			!f.Primitives.Primitive.Qualifiers[0].Compare(test.output.Qualifier) {
			t.Errorf("Parse incorrect, expecting Id: %s, Qualifier: %+v, but got Id: %+v, Qualifier: %+v",
				test.output.Id,
				test.output.Qualifier,
				f.Primitives.Primitive.Id,
				f.Primitives.Primitive.Qualifiers[0])
		}
	}

}

func TestParse_MultiplePrimitives(t *testing.T) {

	tests := []struct {
		input  string
		output []Output
	}{
		{"dst host 192.168.1.10 and tcp 80 and dst 25.25.10.10",
		[]Output{
				{&bpf.Qualifier{Type:  &bpf.QType.Host}, "192.168.1.10"},
				{&bpf.Qualifier{Dir:   &bpf.QDirection.Dst}, "192.168.1.10"},
				{&bpf.Qualifier{Proto: &bpf.QProtocol.TCP}, "80"},
			},
		},
	}

	for _, test := range tests {
		f, err := bpf.Parse(test.input)

		if err != nil {
			t.Errorf("Error parsing: %v", err)
		}

		t.Logf("%+v", f.Primitives.Primitive.Id)

		m := f.Primitives.Qualifiers()
		//var qs []*bpf.Qualifier
		
		//for _, q := range f.Primitives.Primitive.Qualifiers {
		//	qs = append(qs, q)
		//	qMap[q.String()] = append(qMap[q.String()], f.Primitives.Primitive.Id)
		//}
		//
		//next := f.Primitives.Next
		//for next != nil {
		//	t.Logf("%+v", next)
		//	for _, q := range next.Primitive.Qualifiers {
		//		qs = append(qs, q)
		//		qMap[q.String()] = append(qMap[q.String()], next.Primitive.Id)
		//	}
		//	next = next.Next
		//}
		
		//for _, q := range qs {
		//	t.Logf(" %+v", q)
		//}

		t.Logf("%+v", m)
		//if f.Primitives[0].Expression.Primitive

		//then should be a pair qualifier ID!!!
	}

}
