package main

import (
	"log"
	"net"

	"github.com/chennakt9/auth-ms.git/pkg/config"
	"github.com/chennakt9/auth-ms.git/pkg/db"
	"github.com/chennakt9/auth-ms.git/pkg/pb"
	"github.com/chennakt9/auth-ms.git/pkg/service"
	"github.com/chennakt9/auth-ms.git/pkg/utils"
	"google.golang.org/grpc"
)

func main() {
	c, err := config.LoadConfig()

	if err != nil {
		log.Fatalln("Failed to load config", err)
	}

	h := db.Init(c.DBUrl)

	jwt := utils.JWTWrapper{
		SecretKey: c.JWTSecretKey,
		Issuer: "auth-ms",
		ExpirationHours: 24 * 365,
	}

	// fmt.Println("Hey", c.Port)

	lis, err := net.Listen("tcp", c.Port)

	if err != nil {
		log.Fatalln("Failed to listen", err)
	}

	s := service.Server {
		H: h,
		Jwt: jwt,
	}

	grpcServer := grpc.NewServer()

	pb.RegisterAuthServiceServer(grpcServer, &s)

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalln("Failed to serve", err)
	}
}