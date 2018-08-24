using System;
using Xunit;
using PasswordManager.Database;

namespace PasswordManager.Tests
{
	public class PasswordServiceTests
	{
		[Fact]
		public void PlainTextTest()
		{
			var database = new SqlUserDatabase(new SqlConnectionStringProviderMock() { ConnectionStringValue = SqlUserDatabaseTests.connectionString });
			var service = new PlainTextPasswordService(database);
			ExecuteCommon(database, service);
		}

		[Fact]
		public void EncodingTest()
		{
			var database = new SqlUserDatabase(new SqlConnectionStringProviderMock() { ConnectionStringValue = SqlUserDatabaseTests.connectionString });
			var service = new EncodingPasswordService(database);
			ExecuteCommon(database, service);
		}

		[Fact]
		public void SymmetricTest()
		{
			var database = new SqlUserDatabase(new SqlConnectionStringProviderMock() { ConnectionStringValue = SqlUserDatabaseTests.connectionString });
			var service = new SymmetricPasswordService(database);
			ExecuteCommon(database, service);
		}

		[Fact]
		public void AsymmetricTest()
		{
			var database = new SqlUserDatabase(new SqlConnectionStringProviderMock() { ConnectionStringValue = SqlUserDatabaseTests.connectionString });
			var service = new AsymmetricPasswordService(database);
			ExecuteCommon(database, service);
		}

		[Fact]
		public void OneWayTest()
		{
			var database = new SqlUserDatabase(new SqlConnectionStringProviderMock() { ConnectionStringValue = SqlUserDatabaseTests.connectionString });
			var service = new OneWayPasswordService(database);
			ExecuteCommon(database, service);
		}

		[Fact]
		public void SaltedOneWayTest()
		{
			var database = new SqlUserDatabase(new SqlConnectionStringProviderMock() { ConnectionStringValue = SqlUserDatabaseTests.connectionString });
			var service = new SaltedOneWayPasswordService(database);
			ExecuteCommon(database, service);
		}

		private void ExecuteCommon(IUserDatabase userDatabase, IPasswordService passwordService)
		{
			userDatabase.DeleteAll();
			CreateUser(userDatabase, 1, "alice@company.com", String.Empty);
			CreateUser(userDatabase, 2, "bob@company.com", String.Empty);
			CreateUser(userDatabase, 3, "charlie@company.com", String.Empty);
			CreateUser(userDatabase, 4, "david@company.com", String.Empty);
			CreateUser(userDatabase, 5, "edward@company.com", String.Empty);
			CreateUser(userDatabase, 6, "frank@company.com", String.Empty);
			CreateUser(userDatabase, 7, "gina@company.com", String.Empty);
			CreateUser(userDatabase, 8, "howard@company.com", String.Empty);
			CreateUser(userDatabase, 9, "isabella@company.com", String.Empty);
			passwordService.Save(1, "kdI6%jVbgh(9lkjH7eK(tJ^Knghu#");
			passwordService.Save(2, "password123");
			passwordService.Save(3, "password");
			passwordService.Save(4, "MeowMeowKitty");
			passwordService.Save(5, "aaa");
			passwordService.Save(6, "password");
			passwordService.Save(7, "1234");
			passwordService.Save(8, "password");
			passwordService.Save(9, "Butterscotch");
			Assert.True(passwordService.Verify(1, "kdI6%jVbgh(9lkjH7eK(tJ^Knghu#"));
			Assert.True(passwordService.Verify(2, "password123"));
			Assert.True(passwordService.Verify(3, "password"));
			Assert.True(passwordService.Verify(4, "MeowMeowKitty"));
			Assert.True(passwordService.Verify(5, "aaa"));
			Assert.True(passwordService.Verify(6, "password"));
			Assert.True(passwordService.Verify(7, "1234"));
			Assert.True(passwordService.Verify(8, "password"));
			Assert.True(passwordService.Verify(9, "Butterscotch"));
			Assert.False(passwordService.Verify(1, "BadPassword"));
			Assert.False(passwordService.Verify(2, "BadPassword"));
			Assert.False(passwordService.Verify(3, "BadPassword"));
			Assert.False(passwordService.Verify(4, "BadPassword"));
			Assert.False(passwordService.Verify(5, "BadPassword"));
			Assert.False(passwordService.Verify(6, "BadPassword"));
			Assert.False(passwordService.Verify(7, "BadPassword"));
			Assert.False(passwordService.Verify(8, "BadPassword"));
			Assert.False(passwordService.Verify(9, "BadPassword"));
			Assert.True(passwordService.Verify(3, "password"));
			passwordService.Save(3, "NewPassword");
			Assert.False(passwordService.Verify(3, "password"));
			Assert.True(passwordService.Verify(3, "NewPassword"));
			passwordService.Save(3, "password");
			Assert.False(passwordService.Verify(3, "NewPassword"));
			Assert.True(passwordService.Verify(3, "password"));
		}

		private void CreateUser(IUserDatabase userDatabase, int userId, string userName, string userPass)
		{
			userDatabase.Create(new User()
			{
				UserId = userId,
				UserName = userName,
				UserPass = userPass
			});
		}
	}
}
