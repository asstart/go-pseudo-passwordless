package token

import (
	"bytes"
	"fmt"
	"html/template"
)

type TokenMessageBuilder interface {
	GetMessage(token *CodeToken) (string, error)
}

type SimpleMessage struct{}

func (mb *SimpleMessage) GetMessage(token *CodeToken) (string, error) {
	return fmt.Sprintf("Code: %v", token.Value), nil
}

type HTMLTemplateMessage struct {
	Tmplt    *template.Template
	MapToken func(token *CodeToken) interface{}
}

func NewHTMLMessageBuilder(templatePath string, mapTokenFunc func(token *CodeToken) interface{}) (*HTMLTemplateMessage, error) {
	tmplt, err := template.ParseFiles(templatePath)
	if err != nil {
		return nil, err
	}

	err = testTemplate(tmplt, mapTokenFunc)
	if err != nil {
		return nil, err
	}

	return &HTMLTemplateMessage{
		Tmplt:    tmplt,
		MapToken: mapTokenFunc,
	}, nil
}

func (mb *HTMLTemplateMessage) GetMessage(token *CodeToken) (string, error) {
	buf := bytes.NewBufferString("")
	err := mb.Tmplt.Execute(buf, mb.MapToken(token))
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func testTemplate(tmplt *template.Template, mapTokenFunc func(token *CodeToken) interface{}) error {
	tmpToken := CodeToken{}

	buf := bytes.NewBufferString("")

	err := tmplt.Execute(buf, mapTokenFunc(&tmpToken))
	if err != nil {
		return fmt.Errorf("error testing template during initialization: %w", err)
	}
	return nil
}
