using EncryptedChatFlow.Models;
using Microsoft.EntityFrameworkCore;
using System.Threading;
using System.Threading.Tasks;

namespace EncryptedChatFlow.Data
{
    public interface IApplicationDbContext
    {
        DbSet<Message> Messages { get; set; }

        // Add other DbSets as needed

        Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
    }

}
