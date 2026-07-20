using MagicControl.Web.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MagicControl.Web.Data.Migrations;

[DbContext(typeof(MagicControlDbContext))]
[Migration("202607200002_MeshFoundation")]
partial class MeshFoundation
{
    protected override void BuildTargetModel(ModelBuilder modelBuilder)
        => MagicControlModelSnapshotBuilder.Build(modelBuilder);
}
