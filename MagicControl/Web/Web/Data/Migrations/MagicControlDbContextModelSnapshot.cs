using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;

#nullable disable

namespace MagicControl.Web.Data.Migrations;

[DbContext(typeof(MagicControlDbContext))]
partial class MagicControlDbContextModelSnapshot : ModelSnapshot
{
    protected override void BuildModel(ModelBuilder modelBuilder)
        => MagicControlModelSnapshotBuilder.Build(modelBuilder);
}
