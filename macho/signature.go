package macho

import (
	"errors"

	macho "github.com/blacktop/go-macho"

	"github.com/fullsailor/pkcs7"
)

func getSignature(file *macho.File) (*Signature, error) {
	sig := file.CodeSignature()
	if sig == nil {
		return nil, nil
	}
	if len(sig.CodeDirectories) < 1 {
		return nil, errors.New("invalid signature")
	}
	codeDirectory := sig.CodeDirectories[0]
	p7, err := pkcs7.Parse(sig.CMSSignature)
	if err != nil {
		return nil, err
	}
	if len(p7.Certificates) < 1 {
		return nil, errors.New("invalid signature")
	}
	cert := p7.Certificates[0]
	signer := cert.Subject.CommonName
	return &Signature{
		Signer: signer,
		CDHash: codeDirectory.CDHash,
	}, nil
}
