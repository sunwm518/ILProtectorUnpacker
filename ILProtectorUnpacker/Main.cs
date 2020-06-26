using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Serialized;
using AsmResolver.PE.DotNet.Cil;

namespace ILProtectorUnpacker
{
    public class Unpacker
    {
        private static ModuleDefinition _module;
        private static Assembly _assembly;
        private static readonly List<object> ToRemove = new List<object>();

        private static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Please drag & drop the protected file");
                Console.WriteLine("Press any key to exit....");
                Console.ReadKey(true);
                return;
            }
            _module = ModuleDefinition.FromFile(args[0]);
            _assembly = Assembly.LoadFrom(args[0]);
            RuntimeHelpers.RunModuleConstructor(_assembly.ManifestModule.ModuleHandle);

            var invokeField = _module.GetModuleType().Fields.FirstOrDefault(t => t.Name == "Invoke");
            var stringField = _module.GetModuleType().Fields.FirstOrDefault(t => t.Name == "String");

            var strInvokeMethodToken = stringField?.Signature.FieldType.Resolve().Methods
                .FirstOrDefault(m => m.Name == "Invoke")?.MetadataToken.ToInt32();
            var invokeMethodToken = invokeField?.Signature.FieldType.Resolve().Methods
                .FirstOrDefault(m => m.Name == "Invoke")?.MetadataToken.ToInt32();

            if (invokeMethodToken == null) throw new Exception("Cannot find Invoke field");

            var invokeInstance = _assembly.ManifestModule.ResolveField(invokeField.MetadataToken.ToInt32());
            var invokeMethod = _assembly.ManifestModule.ResolveMethod(invokeMethodToken.Value);

            FieldInfo strInstance = null;
            MethodBase strInvokeMethod = null;
            if (strInvokeMethodToken != null)
            {
                strInstance = _assembly.ManifestModule.ResolveField(stringField.MetadataToken.ToInt32());
                strInvokeMethod = _assembly.ManifestModule.ResolveMethod(strInvokeMethodToken.Value);
                ToRemove.Add(stringField);
            }

            ToRemove.Add(invokeField);
            Hooks.ApplyHook();
            foreach (var type in _module.GetAllTypes())
            foreach (var method in type.Methods)
            {
                DecryptMethods(method, invokeMethod, invokeInstance.GetValue(invokeInstance));
                if (strInstance != null)
                    DecryptStrings(method, strInvokeMethod, strInstance.GetValue(strInstance));
            }

            foreach (var obj in ToRemove)
                switch (obj)
                {
                    case FieldDefinition fieldDefinition:
                        _module.TopLevelTypes.Remove(fieldDefinition.Signature.FieldType.Resolve());
                        fieldDefinition.DeclaringType.Fields.Remove(fieldDefinition);
                        break;
                    case SerializedTypeDefinition typeDefinition:
                        typeDefinition.DeclaringType.NestedTypes.Remove(typeDefinition);
                        break;
                }

            foreach (var method in _module.GetModuleType().Methods
                .Where(t => t.ImplementationMap != null && t.ImplementationMap.Scope.Name.Contains("Protect")).ToList())
                _module.GetModuleType().Methods.Remove(method);
            var constructor = _module.GetModuleType().Methods.First(t => t.IsConstructor);

            if (constructor.CilMethodBody != null)
            {
                var methodBody = constructor.CilMethodBody;
                var startIndex = methodBody.Instructions.IndexOf(
                    methodBody.Instructions.FirstOrDefault(t =>
                        t.OpCode == CilOpCodes.Call && ((IMethodDefOrRef) t.Operand).Name ==
                        "GetIUnknownForObject")) - 2;

                var endIndex = methodBody.Instructions.IndexOf(methodBody.Instructions.FirstOrDefault(
                    inst => inst.OpCode == CilOpCodes.Call &&
                            ((IMethodDefOrRef) inst.Operand).Name == "Release")) + 2;

                methodBody.ExceptionHandlers.Remove(methodBody.ExceptionHandlers.FirstOrDefault(
                    exh => exh.HandlerEnd.Offset == methodBody.Instructions[endIndex + 1].Offset));

                for (var i = startIndex; i <= endIndex; i++)
                    methodBody.Instructions.Remove(methodBody.Instructions[startIndex]);
            }

            var extension = Path.GetExtension(args[0]);
            var path = args[0].Remove(args[0].Length - extension.Length, extension.Length) + "-unpacked" + extension;
            _module.Write(path);
        }

        private static void DecryptMethods(MethodDefinition methodDefinition, MethodBase invokeMethod,
            object fieldInstance)
        {
            if (methodDefinition.CilMethodBody == null)
                return;
            var instructions = methodDefinition.CilMethodBody.Instructions;
            if (instructions.Count < 9)
                return;
            if (instructions[0].OpCode.Code != CilCode.Ldsfld)
                return;
            if (((FieldDefinition) instructions[0].Operand).FullName != "i <Module>::Invoke")
                return;
            ToRemove.Add(instructions[3].Operand);
            Hooks.MethodBase = _assembly.ManifestModule.ResolveMethod(methodDefinition.MetadataToken.ToInt32());
            var index = instructions[1].GetLdcI4Constant();
            var dynamicMethodDef =
                new DynamicMethodDefinition(_module, invokeMethod.Invoke(fieldInstance, new object[] {index}));
            methodDefinition.CilMethodBody = dynamicMethodDef.CilMethodBody;
        }

        private static void DecryptStrings(MethodDefinition methodDefinition, MethodBase invokeMethod,
            object fieldInstance)
        {
            if (methodDefinition.CilMethodBody == null)
                return;
            var instructions = methodDefinition.CilMethodBody.Instructions;
            if (instructions.Count < 3)
                return;
            for (var i = 2; i < instructions.Count; i++)
            {
                if (instructions[i].OpCode.Code != CilCode.Callvirt)
                    continue;
                if (instructions[i].Operand.ToString() != "System.String s::Invoke(System.Int32)")
                    continue;
                var index = instructions[i - 1].GetLdcI4Constant();
                instructions[i].OpCode = CilOpCodes.Ldstr;
                instructions[i - 1].OpCode = CilOpCodes.Nop;
                instructions[i - 2].OpCode = CilOpCodes.Nop;
                instructions[i].Operand = invokeMethod.Invoke(fieldInstance, new object[] {index});
            }
        }
    }
}