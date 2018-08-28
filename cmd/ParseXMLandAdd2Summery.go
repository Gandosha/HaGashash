package cmd

import (
	"encoding/xml"
	"os"
	"fmt"
	"io/ioutil"
)

type Nmaprun struct {
	Targetaddresses []Addresses `xml:"nmaprun"`
	Targetports []Ports `xml:"nmaprun"`		
}	
type Addresses struct {
	XMLName  xml.Name `xml:"address"`
	Address string `xml:"addr,attr"̀`
	Addresstype string `xml:"addrtype,attr"̀`
	Vendor string `xml:"vendor,attr"̀`
		
}
type Ports struct {
	XMLName  xml.Name `xml:"ports"`
	Protocol string `xml:"protocol,attr"̀`
	Portid int `xml:"portid,attr"̀`
	State string `xml:"state,attr"̀`
	Name string `xml:"name,attr"̀`		
} 


func XMLparser(xmlpath string) {
	xmlfile, err := os.Open(xmlpath)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	bytes, _ := ioutil.ReadAll(xmlfile)
	defer xmlfile.Close()
	var s Nmaprun
	xml.Unmarshal(bytes, &s)
	fmt.Println(s.Targetaddresses)
}






/* This function decodes the XML document and returns array that represents information about the target.
(The function returns an array of pointers for each strap we read from the file). 
func XmlDecoder(reader io.Reader) ([]Addresses, []Ports, error) {
    var target Target
    if err := xml.NewDecoder(reader).Decode(&target); err != nil {
        return nil, nil, err
    }

    return target.Address, target.Port, nil
} */