// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v4.24.4
// source: events/events.proto

package events

import (
	context "context"

	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	EventSinkService_Publish_FullMethodName = "/events.EventSinkService/Publish"
)

// EventSinkServiceClient is the client API for EventSinkService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type EventSinkServiceClient interface {
	Publish(ctx context.Context, in *EventRequest, opts ...grpc.CallOption) (*EventResponse, error)
}

type eventSinkServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewEventSinkServiceClient(cc grpc.ClientConnInterface) EventSinkServiceClient {
	return &eventSinkServiceClient{cc}
}

func (c *eventSinkServiceClient) Publish(ctx context.Context, in *EventRequest, opts ...grpc.CallOption) (*EventResponse, error) {
	out := new(EventResponse)
	err := c.cc.Invoke(ctx, EventSinkService_Publish_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// EventSinkServiceServer is the server API for EventSinkService service.
// All implementations must embed UnimplementedEventSinkServiceServer
// for forward compatibility
type EventSinkServiceServer interface {
	Publish(context.Context, *EventRequest) (*EventResponse, error)
	mustEmbedUnimplementedEventSinkServiceServer()
}

// UnimplementedEventSinkServiceServer must be embedded to have forward compatible implementations.
type UnimplementedEventSinkServiceServer struct {
}

func (UnimplementedEventSinkServiceServer) Publish(context.Context, *EventRequest) (*EventResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Publish not implemented")
}
func (UnimplementedEventSinkServiceServer) mustEmbedUnimplementedEventSinkServiceServer() {}

// UnsafeEventSinkServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to EventSinkServiceServer will
// result in compilation errors.
type UnsafeEventSinkServiceServer interface {
	mustEmbedUnimplementedEventSinkServiceServer()
}

func RegisterEventSinkServiceServer(s grpc.ServiceRegistrar, srv EventSinkServiceServer) {
	s.RegisterService(&EventSinkService_ServiceDesc, srv)
}

func _EventSinkService_Publish_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EventRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EventSinkServiceServer).Publish(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: EventSinkService_Publish_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EventSinkServiceServer).Publish(ctx, req.(*EventRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// EventSinkService_ServiceDesc is the grpc.ServiceDesc for EventSinkService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var EventSinkService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "events.EventSinkService",
	HandlerType: (*EventSinkServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Publish",
			Handler:    _EventSinkService_Publish_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "events/events.proto",
}
