package service

import (
	"context"
	"net/http"

	"github.com/chennakt9/auth-ms.git/pkg/db"
	"github.com/chennakt9/auth-ms.git/pkg/models"
	"github.com/chennakt9/auth-ms.git/pkg/pb"
	"github.com/chennakt9/auth-ms.git/pkg/utils"
)

type Server struct {
	pb.AuthServiceServer
	H db.Handler
	Jwt utils.JWTWrapper
}

func (s *Server) HealthCheck(ctx context.Context, req *pb.NoParam) (*pb.HealthCheckResponse, error) {
	return &pb.HealthCheckResponse{
		Message: "Auth service is up",
	}, nil
}

func (s *Server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	var user models.User

	if res := s.H.DB.Where(&models.User{Email: req.Email}).First(&user); res.Error == nil {
		return &pb.RegisterResponse{
			Status: http.StatusConflict,
			Error: "A user with this email already exists",
		}, nil
	}

	user.Email = req.Email
	user.Password = utils.HashPassword(req.Password)

	s.H.DB.Create(&user)

	return &pb.RegisterResponse{
		Status: http.StatusOK,
	}, nil
}

func (s *Server) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	var user models.User

	if res := s.H.DB.Where(&models.User{Email: req.Email}).First(&user); res.Error != nil {
		return &pb.LoginResponse{
			Status: http.StatusNotFound,
			Error: "User not found",
		}, nil
	}

	match := utils.CheckPasswordHash(req.Password, user.Password)

	if !match {
		return &pb.LoginResponse{
			Status: http.StatusNotFound,
			Error: "User not found",
		}, nil
	}

	token, _ := s.Jwt.GenerateToken(user)

	return &pb.LoginResponse{
		Status: http.StatusOK,
		Token: token,
	}, nil
}

func (s *Server) Validate(ctx context.Context, req *pb.ValidateRequest) (*pb.ValidateResponse, error) {
	claims, err := s.Jwt.ValidateToken(req.Token)

	if err != nil {
		return &pb.ValidateResponse{
			Status: http.StatusBadRequest,
			Error: err.Error(),
		}, nil
	}

	var user models.User

	if res := s.H.DB.Where(&models.User{Email: claims.Email}).First(&user); res.Error != nil {
		return &pb.ValidateResponse{
			Status: http.StatusNotFound,
			Error: "User not found",
		}, nil
	}

	return &pb.ValidateResponse{
		Status: http.StatusOK,
		UserId: user.Id,
	}, nil
}