package service

import (
	"context"
	"testing"
	"time"

	"github.com/bcetienne/tools-go-token/lib"
	"github.com/bcetienne/tools-go-token/service"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupOTPService(t *testing.T) *service.OTPService {
	// Use low-cost bcrypt (4) for fast testing instead of production cost (14)
	// This reduces test time from ~18s per hash to ~10ms per hash
	hasher := lib.NewPasswordHashWithCost(4)
	os, err := service.NewOTPServiceWithHasher(t.Context(), redisDB, config, hasher)
	require.NoError(t, err)

	// Clear all OTPs to ensure clean state
	err = os.RevokeAllOTPs(t.Context())
	require.NoError(t, err)

	return os
}

// ========================================
// Constructor Tests
// ========================================

func TestNewOTPService(t *testing.T) {
	t.Run("Should create service successfully", func(t *testing.T) {
		_, err := service.NewOTPService(t.Context(), redisDB, config)
		require.NoError(t, err)
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		_, err := service.NewOTPService(context.TODO(), redisDB, config)
		require.NoError(t, err)
	})

	t.Run("Should fail with nil database", func(t *testing.T) {
		_, err := service.NewOTPService(context.Background(), nil, config)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "db is nil")
	})

	t.Run("Should fail with nil OTP ttl", func(t *testing.T) {
		invalidConfig := &lib.Config{OTPTTL: nil}
		_, err := service.NewOTPService(context.Background(), redisDB, invalidConfig)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "one time password ttl is nil")
	})
}

// ========================================
// CreateOTP Tests
// ========================================

func TestCreateOTP(t *testing.T) {
	os := setupOTPService(t)

	t.Run("Should create OTP successfully", func(t *testing.T) {
		userID := 123
		otp, err := os.CreateOTP(context.Background(), userID)

		require.NoError(t, err)
		assert.NotNil(t, otp)
		assert.NotEmpty(t, *otp)
		assert.Equal(t, 6, len(*otp), "OTP should be exactly 6 digits")
		assert.Regexp(t, `^\d{6}$`, *otp, "OTP should be numeric")
	})

	t.Run("Should fail with invalid user ID", func(t *testing.T) {
		_, err := os.CreateOTP(context.Background(), 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid user id")

		_, err = os.CreateOTP(context.Background(), -1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid user id")
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		otp, err := os.CreateOTP(context.TODO(), 123)
		require.NoError(t, err)
		assert.NotNil(t, otp)
		assert.Equal(t, 6, len(*otp))
	})

	t.Run("Should replace existing OTP when creating new one for same user", func(t *testing.T) {
		userID := 456
		otp1, err := os.CreateOTP(context.Background(), userID)
		require.NoError(t, err)

		otp2, err := os.CreateOTP(context.Background(), userID)
		require.NoError(t, err)

		// OTPs should be different (very high probability)
		assert.NotEqual(t, *otp1, *otp2)

		// First OTP should no longer be valid (replaced by second)
		valid1, err := os.VerifyOTP(context.Background(), userID, *otp1)
		require.NoError(t, err)
		assert.False(t, valid1)

		// Second OTP should be valid
		valid2, err := os.VerifyOTP(context.Background(), userID, *otp2)
		require.NoError(t, err)
		assert.True(t, valid2)
	})

	t.Run("Should generate different OTPs for different users", func(t *testing.T) {
		userID1 := 100
		userID2 := 200

		otp1, err := os.CreateOTP(context.Background(), userID1)
		require.NoError(t, err)
		otp2, err := os.CreateOTP(context.Background(), userID2)
		require.NoError(t, err)

		// Very likely to be different (1 in 1,000,000 chance of collision)
		assert.NotEqual(t, *otp1, *otp2)
	})

	t.Run("Should generate OTP with leading zeros", func(t *testing.T) {
		// Generate multiple OTPs to increase chance of getting one with leading zeros
		hasLeadingZero := false
		for i := 0; i < 100; i++ {
			otp, err := os.CreateOTP(context.Background(), 1000+i)
			require.NoError(t, err)
			if (*otp)[0] == '0' {
				hasLeadingZero = true
				assert.Regexp(t, `^\d{6}$`, *otp, "OTP with leading zero should still be 6 digits")
				break
			}
		}
		// This test may occasionally fail due to randomness (~9% chance each iteration)
		assert.True(t, hasLeadingZero, "Should generate OTPs with leading zeros (e.g., '000123')")
	})
}

// ========================================
// VerifyOTP Tests
// ========================================

func TestVerifyOTP(t *testing.T) {
	os := setupOTPService(t)

	t.Run("Should verify valid OTP", func(t *testing.T) {
		userID := 123
		otp, err := os.CreateOTP(context.Background(), userID)
		require.NoError(t, err)

		valid, err := os.VerifyOTP(context.Background(), userID, *otp)
		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("Should return false for non-existent OTP", func(t *testing.T) {
		userID := 999
		valid, err := os.VerifyOTP(context.Background(), userID, "123456")
		require.NoError(t, err)
		assert.False(t, valid)
	})

	t.Run("Should fail with invalid user ID", func(t *testing.T) {
		_, err := os.VerifyOTP(context.Background(), 0, "123456")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid user id")

		_, err = os.VerifyOTP(context.Background(), -1, "123456")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid user id")
	})

	t.Run("Should fail with empty OTP", func(t *testing.T) {
		_, err := os.VerifyOTP(context.Background(), 123, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid otp")
	})

	t.Run("Should fail with OTP too short", func(t *testing.T) {
		_, err := os.VerifyOTP(context.Background(), 123, "12345")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid otp")
	})

	t.Run("Should fail with OTP too long", func(t *testing.T) {
		_, err := os.VerifyOTP(context.Background(), 123, "1234567")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid otp")
	})

	t.Run("Should fail with non-numeric OTP", func(t *testing.T) {
		_, err := os.VerifyOTP(context.Background(), 123, "12345a")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid otp")

		_, err = os.VerifyOTP(context.Background(), 123, "abcdef")
		require.Error(t, err)
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		userID := 123
		otp, err := os.CreateOTP(context.Background(), userID)
		require.NoError(t, err)

		valid, err := os.VerifyOTP(context.TODO(), userID, *otp)
		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("Should return false for wrong OTP", func(t *testing.T) {
		userID := 123
		otp, err := os.CreateOTP(context.Background(), userID)
		require.NoError(t, err)

		// Try wrong OTP
		valid, err := os.VerifyOTP(context.Background(), userID, "000000")
		require.NoError(t, err)
		assert.False(t, valid)

		// Original OTP should still be valid (not consumed by wrong attempt)
		valid, err = os.VerifyOTP(context.Background(), userID, *otp)
		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("Should return false for wrong user ID", func(t *testing.T) {
		userID := 123
		otp, err := os.CreateOTP(context.Background(), userID)
		require.NoError(t, err)

		// Try with different user ID
		valid, err := os.VerifyOTP(context.Background(), 456, *otp)
		require.NoError(t, err)
		assert.False(t, valid)
	})

	t.Run("Should return false for expired OTP", func(t *testing.T) {
		// Create config with very short duration
		otpTTL := "100ms"
		shortConfig := &lib.Config{OTPTTL: &otpTTL}
		hasher := lib.NewPasswordHashWithCost(4)
		shortOS, err := service.NewOTPServiceWithHasher(context.Background(), redisDB, shortConfig, hasher)
		require.NoError(t, err)

		userID := 789
		otp, err := shortOS.CreateOTP(context.Background(), userID)
		require.NoError(t, err)

		// Wait for OTP to expire
		time.Sleep(150 * time.Millisecond)

		// Verify OTP is expired (Redis TTL handles this automatically)
		valid, err := shortOS.VerifyOTP(context.Background(), userID, *otp)
		require.NoError(t, err)
		assert.False(t, valid)
	})

	t.Run("Should auto-revoke OTP after successful verification (single-use)", func(t *testing.T) {
		userID := 999
		otp, err := os.CreateOTP(context.Background(), userID)
		require.NoError(t, err)

		// First verification should succeed
		valid, err := os.VerifyOTP(context.Background(), userID, *otp)
		require.NoError(t, err)
		assert.True(t, valid)

		// Second verification with same OTP should fail (already used)
		valid, err = os.VerifyOTP(context.Background(), userID, *otp)
		require.NoError(t, err)
		assert.False(t, valid, "OTP should be single-use only")
	})

	t.Run("Should verify OTP with leading zeros", func(t *testing.T) {
		userID := 555
		// Keep creating OTPs until we get one with leading zero
		var otp *string
		var err error
		for i := 0; i < 100; i++ {
			otp, err = os.CreateOTP(context.Background(), userID)
			require.NoError(t, err)
			if (*otp)[0] == '0' {
				break
			}
		}

		// Verify the zero-padded OTP works
		if (*otp)[0] == '0' {
			valid, err := os.VerifyOTP(context.Background(), userID, *otp)
			require.NoError(t, err)
			assert.True(t, valid, "OTP with leading zeros should be valid")
		}
	})
}

// ========================================
// Rate Limiting Tests
// ========================================

func TestOTPRateLimiting(t *testing.T) {
	os := setupOTPService(t)

	t.Run("Should block verification after 5 failed attempts", func(t *testing.T) {
		userID := 456
		otp, err := os.CreateOTP(context.Background(), userID)
		require.NoError(t, err)

		// Make 5 failed attempts
		for i := 0; i < 5; i++ {
			valid, err := os.VerifyOTP(context.Background(), userID, "999999")
			require.NoError(t, err)
			assert.False(t, valid)
		}

		// Should now be blocked even with correct OTP
		_, err = os.VerifyOTP(context.Background(), userID, *otp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "max attempts exceeded")
	})

	t.Run("Should allow verification before reaching rate limit", func(t *testing.T) {
		userID := 789
		otp, err := os.CreateOTP(context.Background(), userID)
		require.NoError(t, err)

		// Make 4 failed attempts (just under limit)
		for i := 0; i < 4; i++ {
			valid, err := os.VerifyOTP(context.Background(), userID, "999999")
			require.NoError(t, err)
			assert.False(t, valid)
		}

		// Should still allow verification with correct OTP
		valid, err := os.VerifyOTP(context.Background(), userID, *otp)
		require.NoError(t, err)
		assert.True(t, valid, "Should allow verification before rate limit")
	})

	t.Run("Should reset rate limit when creating new OTP", func(t *testing.T) {
		userID := 321
		_, err := os.CreateOTP(context.Background(), userID)
		require.NoError(t, err)

		// Make 3 failed attempts
		for i := 0; i < 3; i++ {
			_, _ = os.VerifyOTP(context.Background(), userID, "999999")
		}

		// Create new OTP - should reset attempts
		newOTP, err := os.CreateOTP(context.Background(), userID)
		require.NoError(t, err)

		// Should be able to verify new OTP (attempts were reset)
		valid, err := os.VerifyOTP(context.Background(), userID, *newOTP)
		require.NoError(t, err)
		assert.True(t, valid, "New OTP should be verifiable after reset")
	})

	t.Run("Should not increment attempts on successful verification", func(t *testing.T) {
		userID := 654
		otp, err := os.CreateOTP(context.Background(), userID)
		require.NoError(t, err)

		// Successful verification
		valid, err := os.VerifyOTP(context.Background(), userID, *otp)
		require.NoError(t, err)
		assert.True(t, valid)

		// Create new OTP and try again - should start fresh
		newOTP, err := os.CreateOTP(context.Background(), userID)
		require.NoError(t, err)

		// Should work fine (previous success didn't increment attempts)
		valid, err = os.VerifyOTP(context.Background(), userID, *newOTP)
		require.NoError(t, err)
		assert.True(t, valid)
	})
}

// ========================================
// RevokeOTP Tests
// ========================================

func TestRevokeOTP(t *testing.T) {
	os := setupOTPService(t)

	t.Run("Should revoke OTP successfully", func(t *testing.T) {
		userID := 123
		otp, err := os.CreateOTP(context.Background(), userID)
		require.NoError(t, err)

		err = os.RevokeOTP(context.Background(), userID)
		require.NoError(t, err)

		valid, err := os.VerifyOTP(context.Background(), userID, *otp)
		require.NoError(t, err)
		assert.False(t, valid)
	})

	t.Run("Should fail with invalid user ID", func(t *testing.T) {
		err := os.RevokeOTP(context.Background(), 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid user id")

		err = os.RevokeOTP(context.Background(), -1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid user id")
	})

	t.Run("Should succeed when revoking non-existent OTP", func(t *testing.T) {
		err := os.RevokeOTP(context.Background(), 999)
		require.NoError(t, err)
	})

	t.Run("Should succeed when revoking already revoked OTP", func(t *testing.T) {
		userID := 123
		_, err := os.CreateOTP(context.Background(), userID)
		require.NoError(t, err)

		// First revocation
		err = os.RevokeOTP(context.Background(), userID)
		require.NoError(t, err)

		// Second revocation should also succeed
		err = os.RevokeOTP(context.Background(), userID)
		require.NoError(t, err)
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		userID := 123
		_, err := os.CreateOTP(context.Background(), userID)
		require.NoError(t, err)

		err = os.RevokeOTP(context.TODO(), userID)
		require.NoError(t, err)
	})

	t.Run("Should also reset attempts when revoking", func(t *testing.T) {
		userID := 456
		_, err := os.CreateOTP(context.Background(), userID)
		require.NoError(t, err)

		// Make failed attempts
		_, _ = os.VerifyOTP(context.Background(), userID, "999999")
		_, _ = os.VerifyOTP(context.Background(), userID, "888888")

		// Revoke OTP
		err = os.RevokeOTP(context.Background(), userID)
		require.NoError(t, err)

		// Create new OTP - should work without rate limit issues
		newOTP, err := os.CreateOTP(context.Background(), userID)
		require.NoError(t, err)

		valid, err := os.VerifyOTP(context.Background(), userID, *newOTP)
		require.NoError(t, err)
		assert.True(t, valid, "New OTP should work after revocation")
	})
}

// ========================================
// RevokeAllOTPs Tests
// ========================================

func TestRevokeAllOTPs(t *testing.T) {
	os := setupOTPService(t)

	t.Run("Should revoke all OTPs for all users", func(t *testing.T) {
		userID1 := 123
		userID2 := 456

		otp1, err := os.CreateOTP(context.Background(), userID1)
		require.NoError(t, err)
		otp2, err := os.CreateOTP(context.Background(), userID2)
		require.NoError(t, err)

		// Revoke all OTPs
		err = os.RevokeAllOTPs(context.Background())
		require.NoError(t, err)

		// Verify all OTPs are revoked
		valid1, err := os.VerifyOTP(context.Background(), userID1, *otp1)
		require.NoError(t, err)
		assert.False(t, valid1)

		valid2, err := os.VerifyOTP(context.Background(), userID2, *otp2)
		require.NoError(t, err)
		assert.False(t, valid2)
	})

	t.Run("Should also revoke all attempt counters", func(t *testing.T) {
		userID1 := 789
		userID2 := 321

		// Create OTPs and make failed attempts
		_, err := os.CreateOTP(context.Background(), userID1)
		require.NoError(t, err)
		_, _ = os.VerifyOTP(context.Background(), userID1, "999999")

		_, err = os.CreateOTP(context.Background(), userID2)
		require.NoError(t, err)
		_, _ = os.VerifyOTP(context.Background(), userID2, "888888")

		// Revoke all
		err = os.RevokeAllOTPs(context.Background())
		require.NoError(t, err)

		// Create new OTPs - should work fine (attempts cleared)
		newOTP1, err := os.CreateOTP(context.Background(), userID1)
		require.NoError(t, err)
		valid1, err := os.VerifyOTP(context.Background(), userID1, *newOTP1)
		require.NoError(t, err)
		assert.True(t, valid1)

		newOTP2, err := os.CreateOTP(context.Background(), userID2)
		require.NoError(t, err)
		valid2, err := os.VerifyOTP(context.Background(), userID2, *newOTP2)
		require.NoError(t, err)
		assert.True(t, valid2)
	})

	t.Run("Should handle when no OTPs exist", func(t *testing.T) {
		err := os.RevokeAllOTPs(context.Background())
		require.NoError(t, err)
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		err := os.RevokeAllOTPs(context.TODO())
		require.NoError(t, err)
	})
}

// ========================================
// Configuration Tests
// ========================================

func TestOTPInvalidConfig(t *testing.T) {
	t.Run("Should fail with invalid duration format", func(t *testing.T) {
		otpTTL := "invalid-duration"
		invalidConfig := &lib.Config{OTPTTL: &otpTTL}
		_, err := service.NewOTPService(context.Background(), redisDB, invalidConfig)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid OTP TTL format")
		assert.Contains(t, err.Error(), "time: invalid duration")
	})
}

// ========================================
// Uniqueness Tests
// ========================================

func TestOTPUniqueness(t *testing.T) {
	os := setupOTPService(t)

	t.Run("Should handle multiple users with OTPs", func(t *testing.T) {
		// Create OTPs for multiple users
		users := []int{100, 200, 300, 400, 500}
		otps := make(map[int]string)

		for _, userID := range users {
			otp, err := os.CreateOTP(context.Background(), userID)
			require.NoError(t, err)
			otps[userID] = *otp
		}

		// Verify all OTPs are valid for their respective users
		for userID, otpValue := range otps {
			valid, err := os.VerifyOTP(context.Background(), userID, otpValue)
			require.NoError(t, err)
			assert.True(t, valid, "OTP for user %d should be valid", userID)
		}
	})

	t.Run("Should generate statistically unique OTPs", func(t *testing.T) {
		// Generate 100 OTPs and check for duplicates
		// With 1 million possible OTPs, collision probability is very low
		numOTPs := 100
		otpSet := make(map[string]bool)

		for i := 0; i < numOTPs; i++ {
			otp, err := os.CreateOTP(context.Background(), 1000+i)
			require.NoError(t, err)

			if otpSet[*otp] {
				// Collision found - this is possible but very unlikely
				t.Logf("Warning: Duplicate OTP found: %s (expected with low probability)", *otp)
			}
			otpSet[*otp] = true
		}

		// We should have generated unique OTPs (or very close to it)
		// Allow for 1-2 collisions in 100 attempts
		assert.GreaterOrEqual(t, len(otpSet), 98, "Should generate mostly unique OTPs")
	})
}

// ========================================
// Expiration Tests
// ========================================

func TestOTPExpiration(t *testing.T) {
	t.Run("Should expire OTP and attempts together", func(t *testing.T) {
		// Create config with very short duration
		otpTTL := "200ms"
		shortConfig := &lib.Config{OTPTTL: &otpTTL}
		hasher := lib.NewPasswordHashWithCost(4)
		shortOS, err := service.NewOTPServiceWithHasher(context.Background(), redisDB, shortConfig, hasher)
		require.NoError(t, err)

		userID := 777
		otp, err := shortOS.CreateOTP(context.Background(), userID)
		require.NoError(t, err)

		// Make a failed attempt
		_, _ = shortOS.VerifyOTP(context.Background(), userID, "999999")

		// Wait for expiration
		time.Sleep(250 * time.Millisecond)

		// OTP should be expired
		valid, err := shortOS.VerifyOTP(context.Background(), userID, *otp)
		require.NoError(t, err)
		assert.False(t, valid, "OTP should be expired")

		// Should be able to create new OTP (attempts also expired)
		newOTP, err := shortOS.CreateOTP(context.Background(), userID)
		require.NoError(t, err)
		valid, err = shortOS.VerifyOTP(context.Background(), userID, *newOTP)
		require.NoError(t, err)
		assert.True(t, valid, "New OTP should work after expiration")
	})
}
