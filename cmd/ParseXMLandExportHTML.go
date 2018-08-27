package cmd

import (
    "encoding/xml"
    "io"
)

type Target struct {
		XMLName xml.Name `xml:"target"`
		Address []Addresses `xml:"addresses"`
   		//os string
   		Port []Ports `xml:"ports"`
		//vulnerability string
}	
type Addresses struct {
		XMLName xml.Name `xml:"addresses"`
		Address string `xml:"addr,attr"`
		Addresstype string `xml:"addrtype,attr"`
		Vendor string `xml:"vendor,attr"`
}
type Ports struct {
		XMLName xml.Name `xml:"ports"`
		Portid int `xml:"portid,attr"`
		Protocol string `xml:"protocol,attr"`
		State string `xml:"state,attr"`
} 



/* This function decodes the XML document and returns array that represents information about the target.
(The function returns an array of pointers for each strap we read from the file). */
func XmlDecoder(reader io.Reader) ([]Addresses, []Ports, error) {
    var target Target
    if err := xml.NewDecoder(reader).Decode(&target); err != nil {
        return nil, err
    }

    return target.Address, target.Port, nil
} 