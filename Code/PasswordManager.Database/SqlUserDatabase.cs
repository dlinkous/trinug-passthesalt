using System;
using System.Data.SqlClient;
using System.Linq;
using Dapper;

namespace PasswordManager.Database
{
	public class SqlUserDatabase : IUserDatabase
	{
		private readonly ISqlConnectionStringProvider sqlConnectionStringProvider;

		public SqlUserDatabase(ISqlConnectionStringProvider sqlConnectionStringProvider) =>
			this.sqlConnectionStringProvider = sqlConnectionStringProvider;

		public void Create(User user) =>
			UsingConnection(con => con.Execute("INSERT INTO dbo.Users VALUES (@UserId, @UserName, @UserPass)", user));

		public User Read(int userId) =>
			UsingConnection(con => con.Query<User>("SELECT * FROM dbo.Users WHERE UserId = @UserId", new { UserId = userId }).SingleOrDefault());

		public void Update(User user) =>
			UsingConnection(con => con.Execute("UPDATE dbo.Users SET UserName = @UserName, UserPass = @UserPass WHERE UserId = @UserId", user));

		public void Delete(int userId) =>
			UsingConnection(con => con.Execute("DELETE dbo.Users WHERE UserId = @UserId", new { UserId = userId }));

		public void DeleteAll() =>
			UsingConnection(con => con.Execute("DELETE dbo.Users"));

		private void UsingConnection(Action<SqlConnection> action)
		{
			using (var con = new SqlConnection(sqlConnectionStringProvider.ConnectionString))
			{
				con.Open();
				action(con);
			}
		}

		private T UsingConnection<T>(Func<SqlConnection, T> func)
		{
			using (var con = new SqlConnection(sqlConnectionStringProvider.ConnectionString))
			{
				con.Open();
				return func(con);
			}
		}
	}
}
