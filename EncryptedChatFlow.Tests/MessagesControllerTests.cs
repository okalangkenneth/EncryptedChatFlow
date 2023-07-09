using EncryptedChatFlow.Controllers;
using EncryptedChatFlow.Data;
using EncryptedChatFlow.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Moq;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace EncryptedChatFlow.Tests
{
    public class MessagesControllerTests
    {
        private Mock<IHubContext<ChatHub>> mockHubContext;
        private Mock<IApplicationDbContext> mockContext; 
        private Mock<ILogger<MessagesController>> mockLogger;
        private Mock<IDistributedCache> mockCache;
        private MessagesController controller;

        public MessagesControllerTests()
        {
            mockHubContext = new Mock<IHubContext<ChatHub>>();
            mockContext = new Mock<IApplicationDbContext>(); 
            mockLogger = new Mock<ILogger<MessagesController>>();
            mockCache = new Mock<IDistributedCache>();
            controller = new MessagesController(mockHubContext.Object, mockContext.Object, mockLogger.Object, mockCache.Object);
        }

        [Fact]
        public async Task Get_ReturnsOkResult()
        {
            // Arrange
            var mockMessages = new List<Message>
    {
        new Message { Content = "Test message 1", Timestamp = DateTime.Now },
        new Message { Content = "Test message 2", Timestamp = DateTime.Now }
    };

            var mockCache = new Mock<IDistributedCache>();
            mockCache.Setup(c => c.GetAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync((byte[])null); // Simulate a cache miss
            mockCache.Setup(c => c.SetAsync(It.IsAny<string>(), It.IsAny<byte[]>(), It.IsAny<DistributedCacheEntryOptions>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask); // Do nothing when trying to set a cache entry

            var controller = new MessagesController(mockHubContext.Object, mockContext.Object, mockLogger.Object, mockCache.Object);


            // Act
            var result = await controller.Get();

            // Assert
            var objectResult = Assert.IsType<ObjectResult>(result);
            Assert.Equal(500, objectResult.StatusCode); // Check that the status code is 500
            Console.WriteLine(objectResult.Value); // Print the value to the console


        }



    }

}
