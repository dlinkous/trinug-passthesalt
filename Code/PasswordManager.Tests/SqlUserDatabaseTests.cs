using System;
using Xunit;
using PasswordManager.Database;

namespace PasswordManager.Tests
{
	public class SqlUserDatabaseTests
	{
		internal const string connectionString = @"Server=POSEIDON\EXPRESS1;Database=PassTheSalt;Trusted_Connection=true;";

		[Fact]
		public void FullCycleTest()
		{
			var database = new SqlUserDatabase(new SqlConnectionStringProviderMock() { ConnectionStringValue = connectionString });
			database.DeleteAll();
			const int userId = 999;
			const string userName = "Bob";
			const string userPass = "Password123";
			const string newUserPass = "NewPassword321";
			var originalUser = new User()
			{
				UserId = userId,
				UserName = userName,
				UserPass = userPass
			};
			database.Create(originalUser);
			var readUser = database.Read(userId);
			Assert.Equal(userId, readUser.UserId);
			Assert.Equal(userName, readUser.UserName);
			Assert.Equal(userPass, readUser.UserPass);
			readUser.UserPass = newUserPass;
			database.Update(readUser);
			var updatedUser = database.Read(userId);
			Assert.Equal(userId, readUser.UserId);
			Assert.Equal(userName, readUser.UserName);
			Assert.Equal(newUserPass, readUser.UserPass);
			database.Delete(userId);
			var deletedUser = database.Read(userId);
			Assert.Null(deletedUser);
		}
	}
}
