// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.11.2
// source: localstate.proto

package proto

import (
	proto "github.com/golang/protobuf/proto"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

var File_localstate_proto protoreflect.FileDescriptor

var file_localstate_proto_rawDesc = []byte{
	0x0a, 0x10, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x73, 0x74, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x05, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x15, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x73, 0x74,
	0x61, 0x74, 0x65, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x32, 0x8b,
	0x0c, 0x0a, 0x0a, 0x4c, 0x6f, 0x63, 0x61, 0x6c, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x51, 0x0a,
	0x07, 0x47, 0x65, 0x74, 0x44, 0x61, 0x74, 0x61, 0x12, 0x15, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2e, 0x47, 0x65, 0x74, 0x44, 0x61, 0x74, 0x61, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a,
	0x16, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x47, 0x65, 0x74, 0x44, 0x61, 0x74, 0x61, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x17, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x11, 0x22,
	0x0c, 0x2f, 0x76, 0x31, 0x2f, 0x67, 0x65, 0x74, 0x2d, 0x64, 0x61, 0x74, 0x61, 0x3a, 0x01, 0x2a,
	0x12, 0x67, 0x0a, 0x10, 0x47, 0x65, 0x74, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x46, 0x6f, 0x72, 0x4f,
	0x77, 0x6e, 0x65, 0x72, 0x12, 0x16, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x47, 0x65, 0x74,
	0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x17, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x47, 0x65, 0x74, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x22, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x1c, 0x22, 0x17, 0x2f,
	0x76, 0x31, 0x2f, 0x67, 0x65, 0x74, 0x2d, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x2d, 0x66, 0x6f, 0x72,
	0x2d, 0x6f, 0x77, 0x6e, 0x65, 0x72, 0x3a, 0x01, 0x2a, 0x12, 0x76, 0x0a, 0x10, 0x49, 0x74, 0x65,
	0x72, 0x61, 0x74, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x53, 0x70, 0x61, 0x63, 0x65, 0x12, 0x1e, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x49, 0x74, 0x65, 0x72, 0x61, 0x74, 0x65, 0x4e, 0x61, 0x6d,
	0x65, 0x53, 0x70, 0x61, 0x63, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1f, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x49, 0x74, 0x65, 0x72, 0x61, 0x74, 0x65, 0x4e, 0x61, 0x6d,
	0x65, 0x53, 0x70, 0x61, 0x63, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x21,
	0x82, 0xd3, 0xe4, 0x93, 0x02, 0x1b, 0x22, 0x16, 0x2f, 0x76, 0x31, 0x2f, 0x69, 0x74, 0x65, 0x72,
	0x61, 0x74, 0x65, 0x2d, 0x6e, 0x61, 0x6d, 0x65, 0x2d, 0x73, 0x70, 0x61, 0x63, 0x65, 0x3a, 0x01,
	0x2a, 0x12, 0x7c, 0x0a, 0x13, 0x47, 0x65, 0x74, 0x4d, 0x69, 0x6e, 0x65, 0x64, 0x54, 0x72, 0x61,
	0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2e, 0x4d, 0x69, 0x6e, 0x65, 0x64, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2e, 0x4d, 0x69, 0x6e, 0x65, 0x64, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x24, 0x82, 0xd3, 0xe4, 0x93, 0x02,
	0x1e, 0x22, 0x19, 0x2f, 0x76, 0x31, 0x2f, 0x67, 0x65, 0x74, 0x2d, 0x6d, 0x69, 0x6e, 0x65, 0x64,
	0x2d, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x01, 0x2a, 0x12,
	0x68, 0x0a, 0x0e, 0x47, 0x65, 0x74, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x48, 0x65, 0x61, 0x64, 0x65,
	0x72, 0x12, 0x19, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x48,
	0x65, 0x61, 0x64, 0x65, 0x72, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1a, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x1f, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x19,
	0x22, 0x14, 0x2f, 0x76, 0x31, 0x2f, 0x67, 0x65, 0x74, 0x2d, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x2d,
	0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x3a, 0x01, 0x2a, 0x12, 0x4b, 0x0a, 0x07, 0x47, 0x65, 0x74,
	0x55, 0x54, 0x58, 0x4f, 0x12, 0x12, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x55, 0x54, 0x58,
	0x4f, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x13, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2e, 0x55, 0x54, 0x58, 0x4f, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x17, 0x82,
	0xd3, 0xe4, 0x93, 0x02, 0x11, 0x22, 0x0c, 0x2f, 0x76, 0x31, 0x2f, 0x67, 0x65, 0x74, 0x2d, 0x75,
	0x74, 0x78, 0x6f, 0x3a, 0x01, 0x2a, 0x12, 0x84, 0x01, 0x0a, 0x15, 0x47, 0x65, 0x74, 0x50, 0x65,
	0x6e, 0x64, 0x69, 0x6e, 0x67, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x12, 0x20, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x50, 0x65, 0x6e, 0x64, 0x69, 0x6e, 0x67,
	0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x21, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x50, 0x65, 0x6e, 0x64, 0x69,
	0x6e, 0x67, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x26, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x20, 0x22, 0x1b, 0x2f,
	0x76, 0x31, 0x2f, 0x67, 0x65, 0x74, 0x2d, 0x70, 0x65, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x2d, 0x74,
	0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x01, 0x2a, 0x12, 0x96, 0x01,
	0x0a, 0x19, 0x47, 0x65, 0x74, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x53, 0x74, 0x61, 0x74, 0x65, 0x46,
	0x6f, 0x72, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x12, 0x24, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x53, 0x74, 0x61, 0x74, 0x65, 0x46, 0x6f,
	0x72, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x25, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x53,
	0x74, 0x61, 0x74, 0x65, 0x46, 0x6f, 0x72, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x2c, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x26,
	0x22, 0x21, 0x2f, 0x76, 0x31, 0x2f, 0x67, 0x65, 0x74, 0x2d, 0x72, 0x6f, 0x75, 0x6e, 0x64, 0x2d,
	0x73, 0x74, 0x61, 0x74, 0x65, 0x2d, 0x66, 0x6f, 0x72, 0x2d, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61,
	0x74, 0x6f, 0x72, 0x3a, 0x01, 0x2a, 0x12, 0x6c, 0x0a, 0x0f, 0x47, 0x65, 0x74, 0x56, 0x61, 0x6c,
	0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x53, 0x65, 0x74, 0x12, 0x1a, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x2e, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x53, 0x65, 0x74, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1b, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x56, 0x61,
	0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x53, 0x65, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x22, 0x20, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x1a, 0x22, 0x15, 0x2f, 0x76, 0x31, 0x2f,
	0x67, 0x65, 0x74, 0x2d, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x2d, 0x73, 0x65,
	0x74, 0x3a, 0x01, 0x2a, 0x12, 0x68, 0x0a, 0x0e, 0x47, 0x65, 0x74, 0x42, 0x6c, 0x6f, 0x63, 0x6b,
	0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x12, 0x19, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x42,
	0x6c, 0x6f, 0x63, 0x6b, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x1a, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x4e,
	0x75, 0x6d, 0x62, 0x65, 0x72, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x1f, 0x82,
	0xd3, 0xe4, 0x93, 0x02, 0x19, 0x22, 0x14, 0x2f, 0x76, 0x31, 0x2f, 0x67, 0x65, 0x74, 0x2d, 0x62,
	0x6c, 0x6f, 0x63, 0x6b, 0x2d, 0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3a, 0x01, 0x2a, 0x12, 0x58,
	0x0a, 0x0a, 0x47, 0x65, 0x74, 0x43, 0x68, 0x61, 0x69, 0x6e, 0x49, 0x44, 0x12, 0x15, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x43, 0x68, 0x61, 0x69, 0x6e, 0x49, 0x44, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x16, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x43, 0x68, 0x61, 0x69,
	0x6e, 0x49, 0x44, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x1b, 0x82, 0xd3, 0xe4,
	0x93, 0x02, 0x15, 0x22, 0x10, 0x2f, 0x76, 0x31, 0x2f, 0x67, 0x65, 0x74, 0x2d, 0x63, 0x68, 0x61,
	0x69, 0x6e, 0x2d, 0x69, 0x64, 0x3a, 0x01, 0x2a, 0x12, 0x65, 0x0a, 0x0f, 0x53, 0x65, 0x6e, 0x64,
	0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x16, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2e, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x44,
	0x61, 0x74, 0x61, 0x1a, 0x19, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x54, 0x72, 0x61, 0x6e,
	0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x22, 0x1f,
	0x82, 0xd3, 0xe4, 0x93, 0x02, 0x19, 0x22, 0x14, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x65, 0x6e, 0x64,
	0x2d, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x01, 0x2a, 0x12,
	0x68, 0x0a, 0x0e, 0x47, 0x65, 0x74, 0x45, 0x70, 0x6f, 0x63, 0x68, 0x4e, 0x75, 0x6d, 0x62, 0x65,
	0x72, 0x12, 0x19, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x45, 0x70, 0x6f, 0x63, 0x68, 0x4e,
	0x75, 0x6d, 0x62, 0x65, 0x72, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1a, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x45, 0x70, 0x6f, 0x63, 0x68, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x1f, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x19,
	0x22, 0x14, 0x2f, 0x76, 0x31, 0x2f, 0x67, 0x65, 0x74, 0x2d, 0x65, 0x70, 0x6f, 0x63, 0x68, 0x2d,
	0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3a, 0x01, 0x2a, 0x12, 0x71, 0x0a, 0x10, 0x47, 0x65, 0x74,
	0x54, 0x78, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x12, 0x1b, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x54, 0x78, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x4e, 0x75, 0x6d,
	0x62, 0x65, 0x72, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1c, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x2e, 0x54, 0x78, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x22, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x1c,
	0x22, 0x17, 0x2f, 0x76, 0x31, 0x2f, 0x67, 0x65, 0x74, 0x2d, 0x74, 0x78, 0x2d, 0x62, 0x6c, 0x6f,
	0x63, 0x6b, 0x2d, 0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3a, 0x01, 0x2a, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var file_localstate_proto_goTypes = []interface{}{
	(*GetDataRequest)(nil),                 // 0: proto.GetDataRequest
	(*GetValueRequest)(nil),                // 1: proto.GetValueRequest
	(*IterateNameSpaceRequest)(nil),        // 2: proto.IterateNameSpaceRequest
	(*MinedTransactionRequest)(nil),        // 3: proto.MinedTransactionRequest
	(*BlockHeaderRequest)(nil),             // 4: proto.BlockHeaderRequest
	(*UTXORequest)(nil),                    // 5: proto.UTXORequest
	(*PendingTransactionRequest)(nil),      // 6: proto.PendingTransactionRequest
	(*RoundStateForValidatorRequest)(nil),  // 7: proto.RoundStateForValidatorRequest
	(*ValidatorSetRequest)(nil),            // 8: proto.ValidatorSetRequest
	(*BlockNumberRequest)(nil),             // 9: proto.BlockNumberRequest
	(*ChainIDRequest)(nil),                 // 10: proto.ChainIDRequest
	(*TransactionData)(nil),                // 11: proto.TransactionData
	(*EpochNumberRequest)(nil),             // 12: proto.EpochNumberRequest
	(*TxBlockNumberRequest)(nil),           // 13: proto.TxBlockNumberRequest
	(*GetDataResponse)(nil),                // 14: proto.GetDataResponse
	(*GetValueResponse)(nil),               // 15: proto.GetValueResponse
	(*IterateNameSpaceResponse)(nil),       // 16: proto.IterateNameSpaceResponse
	(*MinedTransactionResponse)(nil),       // 17: proto.MinedTransactionResponse
	(*BlockHeaderResponse)(nil),            // 18: proto.BlockHeaderResponse
	(*UTXOResponse)(nil),                   // 19: proto.UTXOResponse
	(*PendingTransactionResponse)(nil),     // 20: proto.PendingTransactionResponse
	(*RoundStateForValidatorResponse)(nil), // 21: proto.RoundStateForValidatorResponse
	(*ValidatorSetResponse)(nil),           // 22: proto.ValidatorSetResponse
	(*BlockNumberResponse)(nil),            // 23: proto.BlockNumberResponse
	(*ChainIDResponse)(nil),                // 24: proto.ChainIDResponse
	(*TransactionDetails)(nil),             // 25: proto.TransactionDetails
	(*EpochNumberResponse)(nil),            // 26: proto.EpochNumberResponse
	(*TxBlockNumberResponse)(nil),          // 27: proto.TxBlockNumberResponse
}
var file_localstate_proto_depIdxs = []int32{
	0,  // 0: proto.LocalState.GetData:input_type -> proto.GetDataRequest
	1,  // 1: proto.LocalState.GetValueForOwner:input_type -> proto.GetValueRequest
	2,  // 2: proto.LocalState.IterateNameSpace:input_type -> proto.IterateNameSpaceRequest
	3,  // 3: proto.LocalState.GetMinedTransaction:input_type -> proto.MinedTransactionRequest
	4,  // 4: proto.LocalState.GetBlockHeader:input_type -> proto.BlockHeaderRequest
	5,  // 5: proto.LocalState.GetUTXO:input_type -> proto.UTXORequest
	6,  // 6: proto.LocalState.GetPendingTransaction:input_type -> proto.PendingTransactionRequest
	7,  // 7: proto.LocalState.GetRoundStateForValidator:input_type -> proto.RoundStateForValidatorRequest
	8,  // 8: proto.LocalState.GetValidatorSet:input_type -> proto.ValidatorSetRequest
	9,  // 9: proto.LocalState.GetBlockNumber:input_type -> proto.BlockNumberRequest
	10, // 10: proto.LocalState.GetChainID:input_type -> proto.ChainIDRequest
	11, // 11: proto.LocalState.SendTransaction:input_type -> proto.TransactionData
	12, // 12: proto.LocalState.GetEpochNumber:input_type -> proto.EpochNumberRequest
	13, // 13: proto.LocalState.GetTxBlockNumber:input_type -> proto.TxBlockNumberRequest
	14, // 14: proto.LocalState.GetData:output_type -> proto.GetDataResponse
	15, // 15: proto.LocalState.GetValueForOwner:output_type -> proto.GetValueResponse
	16, // 16: proto.LocalState.IterateNameSpace:output_type -> proto.IterateNameSpaceResponse
	17, // 17: proto.LocalState.GetMinedTransaction:output_type -> proto.MinedTransactionResponse
	18, // 18: proto.LocalState.GetBlockHeader:output_type -> proto.BlockHeaderResponse
	19, // 19: proto.LocalState.GetUTXO:output_type -> proto.UTXOResponse
	20, // 20: proto.LocalState.GetPendingTransaction:output_type -> proto.PendingTransactionResponse
	21, // 21: proto.LocalState.GetRoundStateForValidator:output_type -> proto.RoundStateForValidatorResponse
	22, // 22: proto.LocalState.GetValidatorSet:output_type -> proto.ValidatorSetResponse
	23, // 23: proto.LocalState.GetBlockNumber:output_type -> proto.BlockNumberResponse
	24, // 24: proto.LocalState.GetChainID:output_type -> proto.ChainIDResponse
	25, // 25: proto.LocalState.SendTransaction:output_type -> proto.TransactionDetails
	26, // 26: proto.LocalState.GetEpochNumber:output_type -> proto.EpochNumberResponse
	27, // 27: proto.LocalState.GetTxBlockNumber:output_type -> proto.TxBlockNumberResponse
	14, // [14:28] is the sub-list for method output_type
	0,  // [0:14] is the sub-list for method input_type
	0,  // [0:0] is the sub-list for extension type_name
	0,  // [0:0] is the sub-list for extension extendee
	0,  // [0:0] is the sub-list for field type_name
}

func init() { file_localstate_proto_init() }
func file_localstate_proto_init() {
	if File_localstate_proto != nil {
		return
	}
	file_localstatetypes_proto_init()
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_localstate_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_localstate_proto_goTypes,
		DependencyIndexes: file_localstate_proto_depIdxs,
	}.Build()
	File_localstate_proto = out.File
	file_localstate_proto_rawDesc = nil
	file_localstate_proto_goTypes = nil
	file_localstate_proto_depIdxs = nil
}