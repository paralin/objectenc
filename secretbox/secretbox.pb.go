// Code generated by protoc-gen-go. DO NOT EDIT.
// source: github.com/aperturerobotics/objectenc/secretbox/secretbox.proto

/*
Package secretbox is a generated protocol buffer package.

It is generated from these files:
	github.com/aperturerobotics/objectenc/secretbox/secretbox.proto

It has these top-level messages:
	SecretBoxMetadata
*/
package secretbox

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// SecretBoxMetadata is the SecretBox encryption metadata.
type SecretBoxMetadata struct {
}

func (m *SecretBoxMetadata) Reset()                    { *m = SecretBoxMetadata{} }
func (m *SecretBoxMetadata) String() string            { return proto.CompactTextString(m) }
func (*SecretBoxMetadata) ProtoMessage()               {}
func (*SecretBoxMetadata) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func init() {
	proto.RegisterType((*SecretBoxMetadata)(nil), "secretbox.SecretBoxMetadata")
}

func init() {
	proto.RegisterFile("github.com/aperturerobotics/objectenc/secretbox/secretbox.proto", fileDescriptor0)
}

var fileDescriptor0 = []byte{
	// 107 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xb2, 0x4f, 0xcf, 0x2c, 0xc9,
	0x28, 0x4d, 0xd2, 0x4b, 0xce, 0xcf, 0xd5, 0x4f, 0x2c, 0x48, 0x2d, 0x2a, 0x29, 0x2d, 0x4a, 0x2d,
	0xca, 0x4f, 0xca, 0x2f, 0xc9, 0x4c, 0x2e, 0xd6, 0xcf, 0x4f, 0xca, 0x4a, 0x4d, 0x2e, 0x49, 0xcd,
	0x4b, 0xd6, 0x2f, 0x4e, 0x4d, 0x2e, 0x4a, 0x2d, 0x49, 0xca, 0xaf, 0x40, 0xb0, 0xf4, 0x0a, 0x8a,
	0xf2, 0x4b, 0xf2, 0x85, 0x38, 0xe1, 0x02, 0x4a, 0xc2, 0x5c, 0x82, 0xc1, 0x60, 0x8e, 0x53, 0x7e,
	0x85, 0x6f, 0x6a, 0x49, 0x62, 0x4a, 0x62, 0x49, 0x62, 0x12, 0x1b, 0x58, 0x99, 0x31, 0x20, 0x00,
	0x00, 0xff, 0xff, 0x73, 0x21, 0xe8, 0xbf, 0x69, 0x00, 0x00, 0x00,
}
