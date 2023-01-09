// Code generated by MockGen. DO NOT EDIT.
// Source: auth/token/service.go

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockService is a mock of Service interface.
type MockService struct {
	ctrl     *gomock.Controller
	recorder *MockServiceMockRecorder
}

// MockServiceMockRecorder is the mock recorder for MockService.
type MockServiceMockRecorder struct {
	mock *MockService
}

// NewMockService creates a new mock instance.
func NewMockService(ctrl *gomock.Controller) *MockService {
	mock := &MockService{ctrl: ctrl}
	mock.recorder = &MockServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockService) EXPECT() *MockServiceMockRecorder {
	return m.recorder
}

// CreateAndDeliver mocks base method.
func (m *MockService) CreateAndDeliver(ctx context.Context, ownerID, destination string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateAndDeliver", ctx, ownerID, destination)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateAndDeliver indicates an expected call of CreateAndDeliver.
func (mr *MockServiceMockRecorder) CreateAndDeliver(ctx, ownerID, destination interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateAndDeliver", reflect.TypeOf((*MockService)(nil).CreateAndDeliver), ctx, ownerID, destination)
}

// Verify mocks base method.
func (m *MockService) Verify(ctx context.Context, ownerID, code string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Verify", ctx, ownerID, code)
	ret0, _ := ret[0].(error)
	return ret0
}

// Verify indicates an expected call of Verify.
func (mr *MockServiceMockRecorder) Verify(ctx, ownerID, code interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Verify", reflect.TypeOf((*MockService)(nil).Verify), ctx, ownerID, code)
}