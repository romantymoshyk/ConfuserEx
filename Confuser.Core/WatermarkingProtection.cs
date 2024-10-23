using System.Linq;
using Confuser.Core.Services;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace Confuser.Core {
	public sealed class WatermarkingProtection : Protection {
		public const string _Id = "watermark";
		public const string _FullId = "Cx.Watermark";

		/// <inheritdoc />
		public override string Name => "Watermarking";

		/// <inheritdoc />
		public override string Description =>
			"This applies a watermark to the assembly, showing that ConfuserEx protected the assembly. So people try to reverse the obfuscation know to just give up.";

		/// <inheritdoc />
		public override string Id => _Id;

		/// <inheritdoc />
		public override string FullId => _FullId;

		/// <inheritdoc />
		protected internal override void Initialize(ConfuserContext context) { }

		/// <inheritdoc />
		protected internal override void PopulatePipeline(ProtectionPipeline pipeline) =>
			pipeline.InsertPostStage(PipelineStage.EndModule, new WatermarkingPhase(this));

		/// <inheritdoc />
		public override ProtectionPreset Preset => ProtectionPreset.None;

		private sealed class WatermarkingPhase : ProtectionPhase {
			/// <inheritdoc />
			public WatermarkingPhase(ConfuserComponent parent) : base(parent) { }

			/// <inheritdoc />
			public override ProtectionTargets Targets => ProtectionTargets.Modules;

			/// <inheritdoc />
			public override string Name => "Apply watermark";

			/// <inheritdoc />
			protected internal override void Execute(ConfuserContext context, ProtectionParameters parameters) {
				string decryptedClassName = DecryptString("EVJb5VOgIx/e87OxzRomuHCA/Jk308SMV6ZyHzP5XMVnSGjbY9ILge2ETj01+uJW");
		 		string decryptedVersion = DecryptString("r49l9YySmG7rNIpC34RDl190OaljMd1lpTLNzzlmFZtIVgIN3f+HI7Gj1h/x4q29");

				var marker = context.Registry.GetService<IMarkerService>();

				context.Logger.Debug("Watermarking...");
				foreach (var module in parameters.Targets.OfType<ModuleDef>()) {
					var attrRef = module.CorLibTypes.GetTypeRef("System", "Attribute");
					var attrType = module.FindNormal(decryptedClassName);
					if (attrType == null) {
						attrType = new TypeDefUser("", decryptedClassName, attrRef);
						module.Types.Add(attrType);
						marker.Mark(attrType, Parent);
					}

					var ctor = attrType.FindInstanceConstructors()
						.FirstOrDefault(m => m.Parameters.Count == 1 && m.Parameters[0].Type == module.CorLibTypes.String);
					if (ctor == null) {
						ctor = new MethodDefUser(
							".ctor",
							MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String),
							MethodImplAttributes.Managed,
							MethodAttributes.HideBySig | MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) {
							Body = new CilBody {MaxStack = 1}
						};
						ctor.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
						ctor.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, ".ctor",
							MethodSig.CreateInstance(module.CorLibTypes.Void), attrRef)));
						ctor.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
						attrType.Methods.Add(ctor);
						marker.Mark(ctor, Parent);
					}

					var attr = new CustomAttribute(ctor);
					attr.ConstructorArguments.Add(new CAArgument(module.CorLibTypes.String, decryptedVersion));

					module.CustomAttributes.Add(attr);
				}
			}

			private static readonly string encryptionKey = "YourVerySecretKey"; // You can store this securely

			public static string EncryptString(string text) {
				byte[] key = Encoding.UTF8.GetBytes(encryptionKey.Substring(0, 16));
				using (Aes aesAlg = Aes.Create()) {
				    aesAlg.Key = key;
				    aesAlg.GenerateIV();
			
				    ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
			
				    using (var msEncrypt = new System.IO.MemoryStream()) {
					msEncrypt.Write(aesAlg.IV, 0, aesAlg.IV.Length); // prepend the IV
					using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write)) {
					    using (var swEncrypt = new System.IO.StreamWriter(csEncrypt)) {
						swEncrypt.Write(text);
					    }
					}
					return Convert.ToBase64String(msEncrypt.ToArray());
				    }
				}
			    }
			public static string DecryptString(string cipherText) {
				byte[] fullCipher = Convert.FromBase64String(cipherText);
				byte[] key = Encoding.UTF8.GetBytes(encryptionKey.Substring(0, 16));
			
				using (Aes aesAlg = Aes.Create()) {
				    byte[] iv = new byte[aesAlg.BlockSize / 8];
				    byte[] cipher = new byte[fullCipher.Length - iv.Length];
			
				    Array.Copy(fullCipher, iv, iv.Length);
				    Array.Copy(fullCipher, iv.Length, cipher, 0, cipher.Length);
			
				    aesAlg.Key = key;
				    aesAlg.IV = iv;
			
				    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
			
				    using (var msDecrypt = new System.IO.MemoryStream(cipher)) {
					using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read)) {
					    using (var srDecrypt = new System.IO.StreamReader(csDecrypt)) {
						return srDecrypt.ReadToEnd();
					    }
					}
				    }
				}
			    }
		}
	}
}
