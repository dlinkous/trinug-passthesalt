using System;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace PasswordManager
{
	public class AsymmetricPasswordService : IPasswordService
	{
		private readonly IUserDatabase userDatabase;

		private const string privateKey = "{\"D\":\"SBK5fbTsbLA1TodiPkYbZL6qyC37/KhaErrZUgaJdxzKeXh2gbtWgcSJnN40+TE50TMVix/IEEn2G9Kt4t442PLJolMODye/ld79JJ+6dvlMLEvyZoOlnngvGrpVOWiCrwz+nyson1G7ZMDxkJlcBqa4mVbM5BXV62iHTPONiWvDUerLWCjGWSeeGSXTRnTIjsYtMXTVkYrPmB86utMloclB+c8PhaZY/+U+e8w/XKWPwqfi8GNdJ6OmOrxMsRKOat25P4bFp6KiXgtRLQ/7Crq8iGdewQ+wBrgeHStQv7X7ADnr1F+jpTf44u+MGOzD9rUOdoZ3jzc1OxA7rBbS7Q==\",\"DP\":\"4BPisPbNM24Q8YHdkqncQMEmU+NzFwTlhDHIBSyHpZNE22Al2amBAP+t0/Th+uYNGD+kG+bC698STd9GBsstVJtDw26+FMe/AX2V0BNkVoOtAVn1E0HyuqF7Al4FJ7X+OnRx+xNYfc4XY3BX7kPN35bI3KsbeXuUJiFCoLFf9V8=\",\"DQ\":\"a5u5ghhbHeka9S+wtVfXk4qwMZAu2xC4pk6GCEM53esG8OQ/ee8JRzYN/XkozCABAtIAgYDoBeRo6IewGmD92C4v7k16hoZtQhKZTZPpwil1Av37D2AUQeVv4frCFHs1uI/qLomCB4+/bhysbzgkCj2La5DTR+uA+C0MoS/Oe1k=\",\"Exponent\":\"AQAB\",\"InverseQ\":\"CNoGBoIDnLi7/VWPoPZEf63lbhHLU+TRhtd9WMGv/LT+1tnY9lJvxIXNM0N+AHRoVDYX/KW7PYvCWC8c8Oy/uciOqNKtP4G62Rz4phRJcV8cG+tF6SY9t/V+FnNynNQhnBCWR2GNgM3Dfz56HtRHCv5EMe1AvwQ2VKm4pH/7Cgs=\",\"Modulus\":\"5qvepoeSTdgk473zMZ/IIKFq8FHdM/MIQJIsCtmM7cNWANyhzRcxojMGVLwzWZpl0frCLlkti4iDMQePWlO71GOYzH0St8ZGmwemu2nRDUlWa4rRCVCAPsgfvbVQPvsc6Ue4Cp+yHpvhugTazSRAKNcfRJCmKRCqPZCK44tDlah4Woa4wPO87rqdJGu+p0g0nQ+9JSfOjzlsqCqUDIwzEYXJ/FjWPFekMj9k/lgARh0HzUlmKTMY5v5/EgoNdTSMuvJyQutDxFXD1MzNUrI9BIl9Qo4R+BcISkdYQpleJS9imxstOuzurExxYs4AhLwZsdI3fByoNEdS0kW/zUBmrQ==\",\"P\":\"7ZHgFwhFYsPUz9OZufd9NYzCBSaluUo0GEx77DCbU9Am9OJwj+s84nh32a2zuRU9vKfgeU4OYaumHoMTFoNwn8s5QfIIgSLXMzPTnHZpjit5bPfUr6P8jofrPiM1RyIUSVBMmN9aBJMS78bt1ZD0Ds/1JbUMuptqoqvczmgonRM=\",\"Q\":\"+JD9x1o9oR3InpyetJvjqYtP+2I1u+1EBkXEzF0i6UUo7XEB0wQbfHmawgXCVJtQVHt24eBAvPHzDS3Obag5+WU9JOYOsH+Cw/pT848rsKB1DNbyJybnXfZqZMrfi+dnueNeJlzn3TkyVDQRSX0EBxabyGJyx27YqCukdHj6JT8=\"}";
		private const string publicKey = "{\"D\":null,\"DP\":null,\"DQ\":null,\"Exponent\":\"AQAB\",\"InverseQ\":null,\"Modulus\":\"5qvepoeSTdgk473zMZ/IIKFq8FHdM/MIQJIsCtmM7cNWANyhzRcxojMGVLwzWZpl0frCLlkti4iDMQePWlO71GOYzH0St8ZGmwemu2nRDUlWa4rRCVCAPsgfvbVQPvsc6Ue4Cp+yHpvhugTazSRAKNcfRJCmKRCqPZCK44tDlah4Woa4wPO87rqdJGu+p0g0nQ+9JSfOjzlsqCqUDIwzEYXJ/FjWPFekMj9k/lgARh0HzUlmKTMY5v5/EgoNdTSMuvJyQutDxFXD1MzNUrI9BIl9Qo4R+BcISkdYQpleJS9imxstOuzurExxYs4AhLwZsdI3fByoNEdS0kW/zUBmrQ==\",\"P\":null,\"Q\":null}";

		public AsymmetricPasswordService(IUserDatabase userDatabase) => this.userDatabase = userDatabase;

		public void Save(int userId, string password)
		{
			var passwordEncrypted = String.Empty;
			using (var rsa = RSA.Create())
			{
				rsa.ImportParameters(JsonConvert.DeserializeObject<RSAParameters>(publicKey));
				var passwordEncryptedBytes = rsa.Encrypt(Encoding.UTF8.GetBytes(password), RSAEncryptionPadding.Pkcs1);
				passwordEncrypted = Convert.ToBase64String(passwordEncryptedBytes);
			}
			var user = userDatabase.Read(userId);
			user.UserPass = passwordEncrypted;
			userDatabase.Update(user);
		}

		public bool Verify(int userId, string password)
		{
			var user = userDatabase.Read(userId);
			var passwordEncryptedBytes = Convert.FromBase64String(user.UserPass);
			using (var rsa = RSA.Create())
			{
				rsa.ImportParameters(JsonConvert.DeserializeObject<RSAParameters>(privateKey));
				var passwordDecryptedBytes = rsa.Decrypt(passwordEncryptedBytes, RSAEncryptionPadding.Pkcs1);
				var passwordDecrypted = Encoding.UTF8.GetString(passwordDecryptedBytes);
				return password == passwordDecrypted;
			}
		}
	}
}
