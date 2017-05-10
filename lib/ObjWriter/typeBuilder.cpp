//===---- typeBuilder.cpp --------------------------------*- C++ -*-===//
//
// type builder implementation using codeview::TypeTableBuilder
//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license.
// See LICENSE file in the project root for full license information.
//
//===----------------------------------------------------------------------===//

#include "typeBuilder.h"
#include "llvm/Support/COFF.h"
#include <sstream>

UserDefinedTypesBuilder::UserDefinedTypesBuilder()
    : Allocator(), TypeTable(Allocator) {}

void UserDefinedTypesBuilder::SetStreamer(MCObjectStreamer *Streamer) {
  assert(this->Streamer == 0);
  assert(Streamer != 0);
  this->Streamer = Streamer;
}

void UserDefinedTypesBuilder::EmitCodeViewMagicVersion() {
  Streamer->EmitValueToAlignment(4);
  Streamer->AddComment("Debug section magic");
  Streamer->EmitIntValue(COFF::DEBUG_SECTION_MAGIC, 4);
}

ClassOptions UserDefinedTypesBuilder::GetCommonClassOptions() {
  return ClassOptions();
}

void UserDefinedTypesBuilder::EmitTypeInformation(
    MCSection *COFFDebugTypesSection) {

  if (TypeTable.empty())
    return;

  Streamer->SwitchSection(COFFDebugTypesSection);
  EmitCodeViewMagicVersion();

  TypeTable.ForEachRecord([&](TypeIndex FieldTypeIndex,
                              ArrayRef<uint8_t> Record) {
	  unsigned index = FieldTypeIndex.getIndex();
	  if (index >= 4671 && index <= 4680)
	  {
		  printf("our index %d\n", index);
	  }
    StringRef S(reinterpret_cast<const char *>(Record.data()), Record.size());
    Streamer->EmitBinaryData(S);
  });
}

unsigned UserDefinedTypesBuilder::GetEnumFieldListType(
    uint64 Count, EnumRecordTypeDescriptor *TypeRecords) {
  FieldListRecordBuilder FLRB(TypeTable);
  FLRB.begin();
#ifndef NDEBUG
  uint64 MaxInt = (unsigned int)-1;
  assert(Count <= MaxInt && "There are too many fields inside enum");
#endif
  for (int i = 0; i < (int)Count; ++i) {
    EnumRecordTypeDescriptor record = TypeRecords[i];
    EnumeratorRecord ER(MemberAccess::Public, APSInt::getUnsigned(record.Value),
                        record.Name);
    FLRB.writeMemberType(ER);
  }
  TypeIndex Type = FLRB.end();
  return Type.getIndex();
}

unsigned UserDefinedTypesBuilder::GetEnumTypeIndex(
    EnumTypeDescriptor TypeDescriptor, EnumRecordTypeDescriptor *TypeRecords) {

  ClassOptions CO = GetCommonClassOptions();
  unsigned FieldListIndex =
      GetEnumFieldListType(TypeDescriptor.ElementCount, TypeRecords);
  TypeIndex FieldListIndexType = TypeIndex(FieldListIndex);
  TypeIndex ElementTypeIndex = TypeIndex(TypeDescriptor.ElementType);

  EnumRecord EnumRecord(TypeDescriptor.ElementCount, CO, FieldListIndexType,
                        TypeDescriptor.Name, TypeDescriptor.UniqueName,
                        ElementTypeIndex);

  TypeIndex Type = TypeTable.writeKnownType(EnumRecord);
  return Type.getIndex();
}

unsigned UserDefinedTypesBuilder::GetClassTypeIndex(
    ClassTypeDescriptor ClassDescriptor) {
  TypeRecordKind Kind =
      ClassDescriptor.IsStruct ? TypeRecordKind::Struct : TypeRecordKind::Class;
  ClassOptions CO = ClassOptions::ForwardReference | GetCommonClassOptions();
  ClassRecord CR(Kind, 0, CO, TypeIndex(), TypeIndex(), TypeIndex(), 0,
                 ClassDescriptor.Name, ClassDescriptor.UniqueName);
  TypeIndex FwdDeclTI = TypeTable.writeKnownType(CR);

  if (ClassDescriptor.IsStruct == false) {
    PointerRecord PointerToClass(FwdDeclTI, 0);
    TypeIndex PointerIndex = TypeTable.writeKnownType(PointerToClass);
    return PointerIndex.getIndex();
  }
  return FwdDeclTI.getIndex();
}

unsigned UserDefinedTypesBuilder::GetCompleteClassTypeIndex(
    ClassTypeDescriptor ClassDescriptor,
    ClassFieldsTypeDescriptior ClassFieldsDescriptor,
    DataFieldDescriptor *FieldsDescriptors) {

  FieldListRecordBuilder FLBR(TypeTable);
  FLBR.begin();

  if (ClassDescriptor.BaseClassId != 0) {
      AddBaseClass(FLBR, ClassDescriptor.BaseClassId);
  }

  for (int i = 0; i < ClassFieldsDescriptor.FieldsCount; ++i) {
    DataFieldDescriptor desc = FieldsDescriptors[i];
    MemberAccess Access = MemberAccess::Public;
    TypeIndex MemberBaseType(desc.FieldTypeIndex);
    int MemberOffsetInBytes = desc.Offset;
    DataMemberRecord DMR(Access, MemberBaseType, MemberOffsetInBytes,
                         desc.Name);
    FLBR.writeMemberType(DMR);
  }
  TypeIndex FieldListIndex = FLBR.end();
  TypeRecordKind Kind =
      ClassDescriptor.IsStruct ? TypeRecordKind::Struct : TypeRecordKind::Class;
  ClassOptions CO = GetCommonClassOptions();
  ClassRecord CR(Kind, ClassFieldsDescriptor.FieldsCount, CO, FieldListIndex,
                 TypeIndex(), TypeIndex(), ClassFieldsDescriptor.Size,
                 ClassDescriptor.Name, ClassDescriptor.UniqueName);
  TypeIndex ClassIndex = TypeTable.writeKnownType(CR);

  if (ClassDescriptor.IsStruct == false) {
      return GetPointerType(ClassIndex);
  }
  return ClassIndex.getIndex();
}

unsigned UserDefinedTypesBuilder::GetArrayTypeIndex(ClassTypeDescriptor ClassDescriptor, ArrayTypeDescriptor ArrayDescriptor) {
    TypeIndex ElementTypeIndex = TypeIndex(ArrayDescriptor.ElementType);
    TypeIndex IndexType = TypeIndex(SimpleTypeKind::Int32);

    ArrayRecord AR(ElementTypeIndex, IndexType, ArrayDescriptor.Size, "");
    TypeIndex ArrayIndex = TypeTable.writeKnownType(AR);

    FieldListRecordBuilder FLBR(TypeTable);
    FLBR.begin();

    unsigned TargetPointerSize = 8;
    unsigned Offset = 0;
    unsigned FieldsCount = 0;

    assert(ClassDescriptor.BaseClassId != 0);
    AddBaseClass(FLBR, ClassDescriptor.BaseClassId);
    FieldsCount++;
    Offset += TargetPointerSize;

    MemberAccess Access = MemberAccess::Public;

    DataMemberRecord CountDMR(Access, ArrayIndex, Offset,
        "count");
    FieldsCount++;
    Offset += TargetPointerSize;

    for (unsigned i = 0; i < ArrayDescriptor.Rank; ++i) { 
        std::stringstream ss; 
        ss << "length" << i;
        char* LengthName = new char[ss.gcount() + 1];
        ss >> LengthName;
        DataMemberRecord LengthDMR(Access, TypeIndex(SimpleTypeKind::Int32), Offset, LengthName);
        FieldsCount++;
        Offset += 4;
    }

    for (unsigned i = 0; i < ArrayDescriptor.Rank; ++i) {
        std::stringstream ss;
        ss << "bounds" << i;
        char* BoundsName = new char[ss.gcount() + 1];
        ss >> BoundsName;
        DataMemberRecord LengthDMR(Access, TypeIndex(SimpleTypeKind::Int32), Offset, BoundsName);
        FieldsCount++;
        Offset += 4;
    }


    DataMemberRecord ArrayDMR(Access, ArrayIndex, Offset,
        "values");
    FLBR.writeMemberType(ArrayDMR);
    FieldsCount++;

    TypeIndex FieldListIndex = FLBR.end();

    assert(ClassDescriptor.IsStruct == false);
    TypeRecordKind Kind = TypeRecordKind::Class;
    ClassOptions CO = GetCommonClassOptions();
    ClassRecord CR(Kind, FieldsCount, CO, FieldListIndex,
        TypeIndex(), TypeIndex(), ArrayDescriptor.Size,
        ClassDescriptor.Name, ClassDescriptor.UniqueName);
    TypeIndex ClassIndex = TypeTable.writeKnownType(CR);

    return GetPointerType(ClassIndex);

}

void UserDefinedTypesBuilder::AddBaseClass(FieldListRecordBuilder& FLBR, unsigned BaseClassId)
{
    MemberAttributes def;
    TypeIndex BaseTypeIndex(BaseClassId);
    BaseClassRecord BCR(def, BaseTypeIndex, 0);
    FLBR.writeMemberType(BCR);
}

unsigned UserDefinedTypesBuilder::GetPointerType(TypeIndex ClassIndex)
{
    PointerRecord PointerToClass(ClassIndex, 0);
    TypeIndex PointerIndex = TypeTable.writeKnownType(PointerToClass);
    return PointerIndex.getIndex();
}