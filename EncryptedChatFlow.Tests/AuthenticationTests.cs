using EncryptedChatFlow.Models.Dtos;
using Microsoft.AspNetCore.Mvc.Testing;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace EncryptedChatFlow.Tests
{
    public class AuthenticationTests : IClassFixture<WebApplicationFactory<Startup>>
    {
        private readonly WebApplicationFactory<Startup> _factory;

        public AuthenticationTests(WebApplicationFactory<Startup> factory)
        {
            _factory = factory;
        }

        [Fact]
        public async Task AuthenticateUser_ReturnsJwtToken()
        {
            // Arrange
            var client = _factory.CreateClient();
            var userTokenRequest = new UserTokenRequest { Email = "okalang.ds@gmail.com.com" };

            // Act
            var response = await client.PostAsync("/api/token", new StringContent(JsonConvert.SerializeObject(userTokenRequest), Encoding.UTF8, "application/json"));

            // Assert
            response.EnsureSuccessStatusCode();
            var responseString = await response.Content.ReadAsStringAsync();
            var tokenResponse = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseString);
            Assert.True(tokenResponse.ContainsKey("token"));
        }
    }

}
