using EncryptedChatFlow.Controllers;
using EncryptedChatFlow.Data;
using EncryptedChatFlow.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Moq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace EncryptedChatFlow.Tests
{
    public class MessagesControllerTests
    {
        private Mock<IHubContext<ChatHub>> mockHubContext;
        private Mock<ApplicationDbContext> mockContext;
        private Mock<ILogger<MessagesController>> mockLogger;
        private Mock<IDistributedCache> mockCache;
        private MessagesController controller;

        public MessagesControllerTests()
        {
            mockHubContext = new Mock<IHubContext<ChatHub>>();
            mockContext = new Mock<ApplicationDbContext>();
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

            var mockDbSet = new Mock<DbSet<Message>>();
            mockDbSet.As<IQueryable<Message>>().Setup(m => m.Provider).Returns(mockMessages.AsQueryable().Provider);
            mockDbSet.As<IQueryable<Message>>().Setup(m => m.Expression).Returns(mockMessages.AsQueryable().Expression);
            mockDbSet.As<IQueryable<Message>>().Setup(m => m.ElementType).Returns(mockMessages.AsQueryable().ElementType);
            mockDbSet.As<IQueryable<Message>>().Setup(m => m.GetEnumerator()).Returns(mockMessages.AsQueryable().GetEnumerator());

            var mockContext = new Mock<ApplicationDbContext>();
            mockContext.Setup(c => c.Messages).Returns(mockDbSet.Object);

            var mockHubContext = new Mock<IHubContext<ChatHub>>();
            var mockLogger = new Mock<ILogger<MessagesController>>();
            var mockCache = new Mock<IDistributedCache>();

            var controller = new MessagesController(mockHubContext.Object, mockContext.Object, mockLogger.Object, mockCache.Object);

            // Act
            var result = await controller.Get();

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result);
            var returnValue = Assert.IsType<List<Message>>(okResult.Value);
            Assert.Equal(mockMessages.Count, returnValue.Count);
        }

    }

}
