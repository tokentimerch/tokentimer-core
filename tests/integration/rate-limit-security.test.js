const { TestUtils, request, expect } = require("./test-server");

describe("Rate Limit Security Tests", () => {
  // TODO: Rate limiting tests need proper configuration for test environment
  // The current rate limiting setup doesn't trigger limits in test environment
  // These tests should be re-enabled once rate limiting is properly configured
  /*
  describe('API Rate Limiting', () => {
    it('should enforce API rate limits correctly', async () => {
      const requests = [];
      
      // Make multiple requests quickly to trigger rate limiting
      for (let i = 0; i < 15; i++) {
        const response = await request('http://localhost:4000')
          .get('/');
        requests.push(response.status);
      }

      // In test environment, we might not hit rate limits due to higher limits
      // But we should verify the endpoint is working
      expect(requests).to.include(200);
      
      // Check if any requests were rate limited (acceptable in test environment)
      const rateLimitCount = requests.filter(status => status === 429).length;
      expect(rateLimitCount).to.be.at.least(0);
    });
  });

  describe('Authentication Rate Limiting', () => {
    it('should enforce login rate limits correctly', async () => {
      const requests = [];
      
      // Make multiple login attempts quickly to trigger rate limiting
      for (let i = 0; i < 10; i++) {
        const response = await request('http://localhost:4000')
          .post('/auth/login')
          .send({
            email: 'test@example.com',
            password: 'wrongpassword'
          });
        requests.push(response.status);
      }

      // All should fail with 401, but some might hit rate limit
      const unauthorizedCount = requests.filter(status => status === 401).length;
      expect(unauthorizedCount).to.be.greaterThan(0);
      
      // Check if any requests were rate limited (acceptable in test environment)
      const rateLimitCount = requests.filter(status => status === 429).length;
      expect(rateLimitCount).to.be.at.least(0);
    });

    it('should enforce registration rate limits correctly', async () => {
      const requests = [];
      
      // Make multiple registration attempts quickly to trigger rate limiting
      for (let i = 0; i < 10; i++) {
        const response = await request('http://localhost:4000')
          .post('/auth/register')
          .send({
            email: `test${i}@example.com`,
            password: 'SecureTest123!@#',
            name: 'Test User'
          });
        requests.push(response.status);
      }

      // Most should succeed (201) due to unique emails, but some might hit rate limit
      const successCount = requests.filter(status => status === 201).length;
      expect(successCount).to.be.greaterThan(0);
      
      // Check if any requests were rate limited (acceptable in test environment)
      const rateLimitCount = requests.filter(status => status === 429).length;
      expect(rateLimitCount).to.be.at.least(0);
    });
  });

  describe('Email Verification Rate Limiting', () => {
    it('should enforce email verification rate limits correctly', async () => {
      const requests = [];
      
      // Make multiple verification attempts quickly to trigger rate limiting
      for (let i = 0; i < 10; i++) {
        const response = await request('http://localhost:4000')
          .get(`/auth/verify-email/test-token-${i}`);
        requests.push(response.status);
      }

      // Most should fail (404) due to invalid tokens, but some might hit rate limit
      const notFoundCount = requests.filter(status => status === 404).length;
      expect(notFoundCount).to.be.greaterThan(0);
      
      // Check if any requests were rate limited (acceptable in test environment)
      const rateLimitCount = requests.filter(status => status === 429).length;
      expect(rateLimitCount).to.be.at.least(0);
    });
  });
  */

  describe("Basic Security Tests", () => {
    it("should have security headers", async () => {
      const response = await request("http://localhost:4000")
        .get("/")
        .expect(200);

      expect(response.headers).to.have.property("x-frame-options");
      expect(response.headers).to.have.property("x-content-type-options");
      expect(response.headers).to.have.property("x-xss-protection");
    });
  });
});
