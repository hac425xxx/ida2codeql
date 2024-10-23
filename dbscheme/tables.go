package dbscheme

import (
	"go/ast"
	gotypes "go/types"
	"log"

	"golang.org/x/tools/go/packages"
)

const (
	EXPR_KIND_BADEXPR                          = 0
	EXPR_KIND_IDENT                            = 1
	EXPR_KIND_ELLIPSIS                         = 2
	EXPR_KIND_INTLIT                           = 3
	EXPR_KIND_FLOATLIT                         = 4
	EXPR_KIND_IMAGLIT                          = 5
	EXPR_KIND_CHARLIT                          = 6
	EXPR_KIND_STRINGLIT                        = 7
	EXPR_KIND_FUNCLIT                          = 8
	EXPR_KIND_COMPOSITELIT                     = 9
	EXPR_KIND_PARENEXPR                        = 10
	EXPR_KIND_SELECTOREXPR                     = 11
	EXPR_KIND_INDEXEXPR                        = 12
	EXPR_KIND_GENERICFUNCTIONINSTANTIATIONEXPR = 13
	EXPR_KIND_GENERICTYPEINSTANTIATIONEXPR     = 14
	EXPR_KIND_SLICEEXPR                        = 15
	EXPR_KIND_TYPEASSERTEXPR                   = 16
	EXPR_KIND_CALLORCONVERSIONEXPR             = 17
	EXPR_KIND_STAREXPR                         = 18
	EXPR_KIND_KEYVALUEEXPR                     = 19
	EXPR_KIND_ARRAYTYPEEXPR                    = 20
	EXPR_KIND_STRUCTTYPEEXPR                   = 21
	EXPR_KIND_FUNCTYPEEXPR                     = 22
	EXPR_KIND_INTERFACETYPEEXPR                = 23
	EXPR_KIND_MAPTYPEEXPR                      = 24
	EXPR_KIND_TYPESETLITERALEXPR               = 25
	EXPR_KIND_PLUSEXPR                         = 26
	EXPR_KIND_MINUSEXPR                        = 27
	EXPR_KIND_NOTEXPR                          = 28
	EXPR_KIND_COMPLEMENTEXPR                   = 29
	EXPR_KIND_DEREFEXPR                        = 30
	EXPR_KIND_ADDRESSEXPR                      = 31
	EXPR_KIND_ARROWEXPR                        = 32
	EXPR_KIND_LOREXPR                          = 33
	EXPR_KIND_LANDEXPR                         = 34
	EXPR_KIND_EQLEXPR                          = 35
	EXPR_KIND_NEQEXPR                          = 36
	EXPR_KIND_LSSEXPR                          = 37
	EXPR_KIND_LEQEXPR                          = 38
	EXPR_KIND_GTREXPR                          = 39
	EXPR_KIND_GEQEXPR                          = 40
	EXPR_KIND_ADDEXPR                          = 41
	EXPR_KIND_SUBEXPR                          = 42
	EXPR_KIND_OREXPR                           = 43
	EXPR_KIND_XOREXPR                          = 44
	EXPR_KIND_MULEXPR                          = 45
	EXPR_KIND_QUOEXPR                          = 46
	EXPR_KIND_REMEXPR                          = 47
	EXPR_KIND_SHLEXPR                          = 48
	EXPR_KIND_SHREXPR                          = 49
	EXPR_KIND_ANDEXPR                          = 50
	EXPR_KIND_ANDNOTEXPR                       = 51
	EXPR_KIND_SENDCHANTYPEEXPR                 = 52
	EXPR_KIND_RECVCHANTYPEEXPR                 = 53
	EXPR_KIND_SENDRCVCHANTYPEEXPR              = 54
)

const (
	STMT_KIND_BADSTMT          = 0
	STMT_KIND_DECLSTMT         = 1
	STMT_KIND_EMPTYSTMT        = 2
	STMT_KIND_LABELEDSTMT      = 3
	STMT_KIND_EXPRSTMT         = 4
	STMT_KIND_SENDSTMT         = 5
	STMT_KIND_INCSTMT          = 6
	STMT_KIND_DECSTMT          = 7
	STMT_KIND_GOSTMT           = 8
	STMT_KIND_DEFERSTMT        = 9
	STMT_KIND_RETURNSTMT       = 10
	STMT_KIND_BREAKSTMT        = 11
	STMT_KIND_CONTINUESTMT     = 12
	STMT_KIND_GOTOSTMT         = 13
	STMT_KIND_FALLTHROUGHSTMT  = 14
	STMT_KIND_BLOCKSTMT        = 15
	STMT_KIND_IFSTMT           = 16
	STMT_KIND_CASECLAUSE       = 17
	STMT_KIND_EXPRSWITCHSTMT   = 18
	STMT_KIND_TYPESWITCHSTMT   = 19
	STMT_KIND_COMMCLAUSE       = 20
	STMT_KIND_SELECTSTMT       = 21
	STMT_KIND_FORSTMT          = 22
	STMT_KIND_RANGESTMT        = 23
	STMT_KIND_ASSIGNSTMT       = 24
	STMT_KIND_DEFINESTMT       = 25
	STMT_KIND_ADDASSIGNSTMT    = 26
	STMT_KIND_SUBASSIGNSTMT    = 27
	STMT_KIND_MULASSIGNSTMT    = 28
	STMT_KIND_QUOASSIGNSTMT    = 29
	STMT_KIND_REMASSIGNSTMT    = 30
	STMT_KIND_ANDASSIGNSTMT    = 31
	STMT_KIND_ORASSIGNSTMT     = 32
	STMT_KIND_XORASSIGNSTMT    = 33
	STMT_KIND_SHLASSIGNSTMT    = 34
	STMT_KIND_SHRASSIGNSTMT    = 35
	STMT_KIND_ANDNOTASSIGNSTMT = 36
)

var defaultSnippet = AddDefaultSnippet(`
/** Duplicate code **/

duplicateCode(
  unique int id : @duplication,
  varchar(900) relativePath : string ref,
  int equivClass : int ref);

similarCode(
  unique int id : @similarity,
  varchar(900) relativePath : string ref,
  int equivClass : int ref);

@duplication_or_similarity = @duplication | @similarity;

tokens(
  int id : @duplication_or_similarity ref,
  int offset : int ref,
  int beginLine : int ref,
  int beginColumn : int ref,
  int endLine : int ref,
  int endColumn : int ref);

/** External data **/

externalData(
  int id : @externalDataElement,
  varchar(900) path : string ref,
  int column: int ref,
  varchar(900) value : string ref
);

snapshotDate(unique date snapshotDate : date ref);

sourceLocationPrefix(varchar(900) prefix : string ref);
`)

// Copied directly from the XML dbscheme
var xmlSnippet = AddDefaultSnippet(`
/*
 * XML Files
 */

xmlEncoding(
  unique int id: @file ref,
  string encoding: string ref
);

xmlDTDs(
  unique int id: @xmldtd,
  string root: string ref,
  string publicId: string ref,
  string systemId: string ref,
  int fileid: @file ref
);

xmlElements(
  unique int id: @xmlelement,
  string name: string ref,
  int parentid: @xmlparent ref,
  int idx: int ref,
  int fileid: @file ref
);

xmlAttrs(
  unique int id: @xmlattribute,
  int elementid: @xmlelement ref,
  string name: string ref,
  string value: string ref,
  int idx: int ref,
  int fileid: @file ref
);

xmlNs(
  int id: @xmlnamespace,
  string prefixName: string ref,
  string URI: string ref,
  int fileid: @file ref
);

xmlHasNs(
  int elementId: @xmlnamespaceable ref,
  int nsId: @xmlnamespace ref,
  int fileid: @file ref
);

xmlComments(
  unique int id: @xmlcomment,
  string text: string ref,
  int parentid: @xmlparent ref,
  int fileid: @file ref
);

xmlChars(
  unique int id: @xmlcharacters,
  string text: string ref,
  int parentid: @xmlparent ref,
  int idx: int ref,
  int isCDATA: int ref,
  int fileid: @file ref
);

@xmlparent = @file | @xmlelement;
@xmlnamespaceable = @xmlelement | @xmlattribute;

xmllocations(
  int xmlElement: @xmllocatable ref,
  int location: @location_default ref
);

@xmllocatable = @xmlcharacters | @xmlelement | @xmlcomment | @xmlattribute | @xmldtd | @file | @xmlnamespace;
`)

// Compiler diagnostic tables
var CompilationType = NewPrimaryKeyType("@compilation")

/**
 * An invocation of the compiler. Note that more than one file may be
 * compiled per invocation. For example, this command compiles three
 * source files:
 *
 *   go build a.go b.go c.go
 *
 * The `id` simply identifies the invocation, while `cwd` is the working
 * directory from which the compiler was invoked.
 */
var CompilationsTable = NewTable("compilations",
	EntityColumn(CompilationType, "id").Key(),
	StringColumn("cwd"),
)

/**
 * The arguments that were passed to the extractor for a compiler
 * invocation. If `id` is for the compiler invocation
 *
 *   go build a.go b.go c.go
 *
 * then typically there will be rows for
 *
 * num | arg
 * --- | ---
 * 0   | *path to extractor*
 * 1   | `--`
 * 2   | a.go
 * 3   | b.go
 * 4   | c.go
 */
var CompilationArgsTable = NewTable("compilation_args",
	EntityColumn(CompilationType, "id"),
	IntColumn("num"),
	StringColumn("arg"),
).KeySet("id", "num")

/**
 * The source files that are compiled by a compiler invocation.
 * If `id` is for the compiler invocation
 *
 *   go build a.go b.go c.go
 *
 * then there will be rows for
 *
 * num | arg
 * --- | ---
 * 0   | a.go
 * 1   | b.go
 * 2   | c.go
 */
var CompilationCompilingFilesTable = NewTable("compilation_compiling_files",
	EntityColumn(CompilationType, "id"),
	IntColumn("num"),
	EntityColumn(FileType, "file"),
).KeySet("id", "num")

type CompilationTypeKind int

const (
	FRONTEND_CPU_SECONDS = iota
	FRONTEND_ELAPSED_SECONDS
	EXTRACTOR_CPU_SECONDS
	EXTRACTOR_ELAPSED_SECONDS
)

/**
 * The time taken by the extractor for a compiler invocation.
 *
 * For each file `num`, there will be rows for
 *
 * kind | seconds
 * ---- | ---
 * 1    | CPU seconds used by the extractor frontend
 * 2    | Elapsed seconds during the extractor frontend
 * 3    | CPU seconds used by the extractor backend
 * 4    | Elapsed seconds during the extractor backend
 */
var CompilationTimeTable = NewTable("compilation_time",
	EntityColumn(CompilationType, "id"),
	IntColumn("num"),
	IntColumn("kind"),
	FloatColumn("secs"),
).KeySet("id", "num", "kind")

var DiagnosticType = NewPrimaryKeyType("@diagnostic")

/**
 * An error or warning generated by the extractor.
 * The diagnostic message `diagnostic` was generated during compiler
 * invocation `compilation`, and is the `file_number_diagnostic_number`th
 * message generated while extracting the `file_number`th file of that
 * invocation.
 */
var DiagnosticForTable = NewTable("diagnostic_for",
	EntityColumn(DiagnosticType, "diagnostic").Unique(),
	EntityColumn(CompilationType, "compilation"),
	IntColumn("file_number"),
	IntColumn("file_number_diagnostic_number"),
)

/**
 * If extraction was successful, then `cpu_seconds` and
 * `elapsed_seconds` are the CPU time and elapsed time (respectively)
 * that extraction took for compiler invocation `id`.
 */
var CompilationFinishedTable = NewTable("compilation_finished",
	EntityColumn(CompilationType, "id").Unique(),
	FloatColumn("cpu_seconds"),
	FloatColumn("elapsed_seconds"),
)

var DiagnosticsTable = NewTable("diagnostics",
	EntityColumn(DiagnosticType, "id").Key(),
	IntColumn("severity"),
	StringColumn("error_tag"),
	StringColumn("error_message"),
	StringColumn("full_error_message"),
	EntityColumn(LocationType, "location"),
)

// ContainerType is the type of files and folders
var ContainerType = NewUnionType("@container")

// LocatableType is the type of program entities that have locations
var LocatableType = NewUnionType("@locatable")

// Adds xmllocatable as a locatable
var XmlLocatableAsLocatable = LocatableType.AddChild("@xmllocatable")

// NodeType is the type of AST nodes
var NodeType = NewUnionType("@node", LocatableType)

// DocumentableType is the type of AST nodes to which documentation can be attached
var DocumentableType = NewUnionType("@documentable", NodeType)

// ExprParentType is the type of AST nodes that can have expressions as children
var ExprParentType = NewUnionType("@exprparent", NodeType)

// ModExprParentType is the type of go.mod nodes that can have go.mod expressions as children
var ModExprParentType = NewUnionType("@modexprparent", NodeType)

// FieldParentType is the type of AST nodes that can have fields as children
var FieldParentType = NewUnionType("@fieldparent", NodeType)

// StmtParentType is the type of AST nodes that can have statements as children
var StmtParentType = NewUnionType("@stmtparent", NodeType)

// DeclParentType is the type of AST nodes that can have declarations as children
var DeclParentType = NewUnionType("@declparent", NodeType)

// TypeParamDeclParentType is the type of AST nodes that can have type parameter declarations as children
var TypeParamDeclParentType = NewUnionType("@typeparamdeclparent", NodeType)

// FuncDefType is the type of AST nodes that define functions, that is, function
// declarations and function literals
var FuncDefType = NewUnionType("@funcdef", StmtParentType, ExprParentType)

// ScopeNodeType is the type of AST nodes that may have a scope attached to them
var ScopeNodeType = NewUnionType("@scopenode", NodeType)

// LocationDefaultType is the type of source locations
var LocationDefaultType = NewPrimaryKeyType("@location_default")

// FileType is the type of file AST nodes
var FileType = NewPrimaryKeyType("@file", ContainerType, DocumentableType, ExprParentType, ModExprParentType, DeclParentType, ScopeNodeType)

// FolderType is the type of folders
var FolderType = NewPrimaryKeyType("@folder", ContainerType)

// CommentGroupType is the type of comment groups
var CommentGroupType = NewPrimaryKeyType("@comment_group", NodeType)

// CommentType is the type of comments
var CommentType = NewPrimaryKeyType("@comment", NodeType)

// ExprType is the type of expression AST nodes
var ExprType = NewPrimaryKeyType("@expr", ExprParentType)

// FieldType is the type of field AST nodes
var FieldType = NewPrimaryKeyType("@field", DocumentableType, ExprParentType)

// StmtType is the type of statement AST nodes
var StmtType = NewPrimaryKeyType("@stmt", ExprParentType, StmtParentType)

// DeclType is the type of declaration AST nodes
var DeclType = NewPrimaryKeyType("@decl", ExprParentType, StmtParentType, FieldParentType)

// TypeParamDeclType is the type of type parameter declaration AST nodes
var TypeParamDeclType = NewPrimaryKeyType("@typeparamdecl", DocumentableType, ExprParentType)

// SpecType is the type of spec AST nodes
var SpecType = NewPrimaryKeyType("@spec", ExprParentType, DocumentableType)

// TypeType is the type of types
var TypeType = NewPrimaryKeyType("@type")

// LocationType is an alias for LocationDefaultType
var LocationType = NewAliasType("@location", LocationDefaultType)

// SourceLineType is an alias for LocatableType
var SourceLineType = NewAliasType("@sourceline", LocatableType)

// CommentKind is a case type for distinguishing different kinds of comments
var CommentKind = NewCaseType(CommentType, "kind")

// SlashSlashComment is the type of single-line comments starting with a double slash
var SlashSlashComment = CommentKind.NewBranch("@slashslashcomment")

// SlashStarComment is the type of block comments delimited by stars and slashes
var SlashStarComment = CommentKind.NewBranch("@slashstarcomment")

// ExprKind is a case type for distinguishing different kinds of expression AST nodes
var ExprKind = NewCaseType(ExprType, "kind")

// BadExpr is type of bad (that is, unparseable) expression AST nodes
var BadExpr = ExprKind.NewBranch("@badexpr")

// IdentExpr is the type of identifier expression AST nodes
var IdentExpr = ExprKind.NewBranch("@ident")

// EllipsisExpr is the type of ellipsis expression AST nodes
var EllipsisExpr = ExprKind.NewBranch("@ellipsis")

// BasicLitExpr is the type of basic (that is, primitive) literal expression AST nodes
var BasicLitExpr = NewUnionType("@basiclit")

// IntLitExpr is a case type for dishinguishing different kinds of literal expression AST nodes
var IntLitExpr = ExprKind.NewBranch("@intlit", BasicLitExpr)

// FloatLitExpr is the type of floating-point literal expression AST nodes
var FloatLitExpr = ExprKind.NewBranch("@floatlit", BasicLitExpr)

// ImagLitExpr is the type of imaginary literal expression AST nodes
var ImagLitExpr = ExprKind.NewBranch("@imaglit", BasicLitExpr)

// CharLitExpr is the type of character literal expression AST nodes
var CharLitExpr = ExprKind.NewBranch("@charlit", BasicLitExpr)

// StringLitExpr is the type of string literal expression AST nodes
var StringLitExpr = ExprKind.NewBranch("@stringlit", BasicLitExpr)

// FuncLitExpr is the type of function literal expression AST nodes
var FuncLitExpr = ExprKind.NewBranch("@funclit", FuncDefType)

// CompositeLitExpr is the type of composite literal expression AST nodes
var CompositeLitExpr = ExprKind.NewBranch("@compositelit")

// ParenExpr is the type of parenthesis expression AST nodes
var ParenExpr = ExprKind.NewBranch("@parenexpr")

// SelectorExpr is the type of selector expression AST nodes
var SelectorExpr = ExprKind.NewBranch("@selectorexpr")

// IndexExpr is the type of AST nodes for index expressions and generic type
// instantiation expressions with one type argument. Note that syntactically
// unambiguous generic instantiations will be extracted as
// `GenericTypeInstantiationExpr`.
var IndexExpr = ExprKind.NewBranch("@indexexpr")

// GenericFunctionInstantiationExpr is the type of AST nodes that represent an instantiation
// of a generic type. These correspond to some index expression AST nodes and all index
// list expression AST nodes.
var GenericFunctionInstantiationExpr = ExprKind.NewBranch("@genericfunctioninstantiationexpr")

// GenericTypeInstantiationExpr is the type of AST nodes that represent an instantiation
// of a generic type. These correspond to some index expression AST nodes and all index
// list expression AST nodes. Note some syntactically ambiguous instantations are
// extracted as an `IndexExpr` to be disambiguated in QL later.
var GenericTypeInstantiationExpr = ExprKind.NewBranch("@generictypeinstantiationexpr")

// SliceExpr is the type of slice expression AST nodes
var SliceExpr = ExprKind.NewBranch("@sliceexpr")

// TypeAssertExpr is the type of type assertion expression AST nodes
var TypeAssertExpr = ExprKind.NewBranch("@typeassertexpr")

// CallOrConversionExpr is the type of call and conversion expression AST nodes
// (which cannot be distinguished by purely syntactic criteria)
var CallOrConversionExpr = ExprKind.NewBranch("@callorconversionexpr")

// StarExpr is the type of star expression AST nodes
var StarExpr = ExprKind.NewBranch("@starexpr")

// OperatorExpr is the type of operator expression AST nodes
var OperatorExpr = NewUnionType("@operatorexpr")

// LogicalExpr is the type of logical operator expression AST nodes
var LogicalExpr = NewUnionType("@logicalexpr", OperatorExpr)

// ArithmeticExpr is the type of arithmetic operator expression AST nodes
var ArithmeticExpr = NewUnionType("@arithmeticexpr", OperatorExpr)

// BitwiseExpr is the type of bitwise operator expression AST nodes
var BitwiseExpr = NewUnionType("@bitwiseexpr", OperatorExpr)

// UnaryExpr is the type of unary operator expression AST nodes
var UnaryExpr = NewUnionType("@unaryexpr", OperatorExpr)

// LogicalUnaryExpr is the type of logical unary operator expression AST nodes
var LogicalUnaryExpr = NewUnionType("@logicalunaryexpr", UnaryExpr, LogicalExpr)

// BitwiseUnaryExpr is the type of bitwise unary operator expression AST nodes
var BitwiseUnaryExpr = NewUnionType("@bitwiseunaryexpr", UnaryExpr, BitwiseExpr)

// ArithmeticUnaryExpr is the type of arithmetic unary operator expression AST nodes
var ArithmeticUnaryExpr = NewUnionType("@arithmeticunaryexpr", UnaryExpr, ArithmeticExpr)

// BinaryExpr is the type of binary operator expression AST nodes
var BinaryExpr = NewUnionType("@binaryexpr", OperatorExpr)

// LogicalBinaryExpr is the type of logical binary operator expression AST nodes
var LogicalBinaryExpr = NewUnionType("@logicalbinaryexpr", BinaryExpr, LogicalExpr)

// BitwiseBinaryExpr is the type of bitwise binary operator expression AST nodes
var BitwiseBinaryExpr = NewUnionType("@bitwisebinaryexpr", BinaryExpr, BitwiseExpr)

// ArithmeticBinaryExpr is the type of arithmetic binary operator expression AST nodes
var ArithmeticBinaryExpr = NewUnionType("@arithmeticbinaryexpr", BinaryExpr, ArithmeticExpr)

// ShiftExpr is the type of shift operator expression AST nodes
var ShiftExpr = NewUnionType("@shiftexpr", BitwiseBinaryExpr)

// Comparison is the type of comparison operator expression AST nodes
var Comparison = NewUnionType("@comparison", BinaryExpr)

// EqualityTest is the type of equality operator expression AST nodes
var EqualityTest = NewUnionType("@equalitytest", Comparison)

// RelationalComparison is the type of relational operator expression AST nodes
var RelationalComparison = NewUnionType("@relationalcomparison", Comparison)

// KeyValueExpr is the type of key-value expression AST nodes
var KeyValueExpr = ExprKind.NewBranch("@keyvalueexpr")

// ArrayTypeExpr is the type of array type AST nodes
var ArrayTypeExpr = ExprKind.NewBranch("@arraytypeexpr")

// StructTypeExpr is the type of struct type AST nodes
var StructTypeExpr = ExprKind.NewBranch("@structtypeexpr", FieldParentType)

// FuncTypeExpr is the type of function type AST nodes
var FuncTypeExpr = ExprKind.NewBranch("@functypeexpr", FieldParentType, ScopeNodeType)

// InterfaceTypeExpr is the type of interface type AST nodes
var InterfaceTypeExpr = ExprKind.NewBranch("@interfacetypeexpr", FieldParentType)

// MapTypeExpr is the type of map type AST nodes
var MapTypeExpr = ExprKind.NewBranch("@maptypeexpr")

// TypeSetLiteralExpr is the type of type set literal type AST nodes
var TypeSetLiteralExpr = ExprKind.NewBranch("@typesetliteralexpr")

// ChanTypeExpr is the type of channel type AST nodes
var ChanTypeExpr = NewUnionType("@chantypeexpr")

// UnaryExprs is a map from unary operator tokens to the corresponding AST node type
var UnaryExprs = map[string]*BranchType{
	"cot_ref":  ExprKind.NewBranch("@addressexpr", UnaryExpr),
	"cot_lnot": ExprKind.NewBranch("@notexpr", LogicalUnaryExpr),
	//token.ADD:   ExprKind.NewBranch("@plusexpr", ArithmeticUnaryExpr),
	//token.SUB:   ExprKind.NewBranch("@minusexpr", ArithmeticUnaryExpr),
	//token.XOR:   ExprKind.NewBranch("@complementexpr", BitwiseUnaryExpr),
	//token.MUL:   ExprKind.NewBranch("@derefexpr", UnaryExpr),
	//token.ARROW: ExprKind.NewBranch("@arrowexpr", UnaryExpr),
}

// BinaryExprs is a map from binary operator tokens to the corresponding AST node type
var BinaryExprs = map[string]*BranchType{
	"cot_lor": ExprKind.NewBranch("@lorexpr", LogicalBinaryExpr),
	"cot_add": ExprKind.NewBranch("@addexpr", ArithmeticBinaryExpr),
	"cot_sle": ExprKind.NewBranch("@lssexpr", RelationalComparison),
}

// ChanTypeExprs is a map from channel type expressions to the corresponding AST node type
var ChanTypeExprs = map[ast.ChanDir]*BranchType{
	ast.SEND:            ExprKind.NewBranch("@sendchantypeexpr", ChanTypeExpr),
	ast.RECV:            ExprKind.NewBranch("@recvchantypeexpr", ChanTypeExpr),
	ast.SEND | ast.RECV: ExprKind.NewBranch("@sendrcvchantypeexpr", ChanTypeExpr),
}

var HexrayExprKinds = map[string]int{
	"cot_sle":  EXPR_KIND_LEQEXPR,
	"cot_ule":  EXPR_KIND_LEQEXPR,
	"cot_slt":  EXPR_KIND_LSSEXPR,
	"cot_ult":  EXPR_KIND_LSSEXPR,
	"cot_bnot": EXPR_KIND_NOTEXPR,

	"cot_sge":  EXPR_KIND_GEQEXPR,
	"cot_uge":  EXPR_KIND_GEQEXPR,
	"cot_sgt":  EXPR_KIND_GTREXPR,
	"cot_ugt":  EXPR_KIND_GTREXPR,
	"cot_band": EXPR_KIND_ANDEXPR,

	"cot_add": EXPR_KIND_ADDEXPR,
	"cot_lor": EXPR_KIND_LOREXPR,
	"cot_mul": EXPR_KIND_MULEXPR,
	"cot_sub": EXPR_KIND_SUBEXPR,
	"cot_eq":  EXPR_KIND_EQLEXPR,
	"cot_ne":  EXPR_KIND_NEQEXPR,

	"cot_sshr": EXPR_KIND_SHREXPR,
	"cot_ushr": EXPR_KIND_SHREXPR,
	"cot_bor":  EXPR_KIND_OREXPR,
	"cot_xor":  EXPR_KIND_XOREXPR,
	"cot_smod": EXPR_KIND_REMEXPR,

	"cot_lnot": EXPR_KIND_NOTEXPR,
	"cot_land": EXPR_KIND_LANDEXPR,
	"cot_ref":  EXPR_KIND_ADDRESSEXPR,

	"Parameter":  EXPR_KIND_IDENT,
	"Identifier": EXPR_KIND_IDENT,
	"MemberPtr":  EXPR_KIND_SELECTOREXPR,

	"Star":   EXPR_KIND_STAREXPR,
	"Call":   EXPR_KIND_CALLORCONVERSIONEXPR,
	"Number": EXPR_KIND_INTLIT,

	"ArrayIndexAccess": EXPR_KIND_INDEXEXPR,
	"LabelIdent":       EXPR_KIND_IDENT,
}

func GetHexrayExprKind(e string) int {
	k, err := HexrayExprKinds[e]
	if !err {
		log.Fatalf("unsupported hexray expr %s", e)
	}
	return k
}

var HexrayStmtKinds = map[string]int{
	"Block":          STMT_KIND_BLOCKSTMT,
	"Expression":     STMT_KIND_EXPRSTMT,
	"Return":         STMT_KIND_RETURNSTMT,
	"If":             STMT_KIND_IFSTMT,
	"LocalDecl":      STMT_KIND_DECLSTMT,
	"While":          STMT_KIND_FORSTMT,
	"Do":             STMT_KIND_FORSTMT,
	"For":            STMT_KIND_FORSTMT,
	"cot_asg":        STMT_KIND_ASSIGNSTMT,
	"cot_preinc":     STMT_KIND_INCSTMT,
	"cot_predec":     STMT_KIND_DECSTMT,
	"cot_postdec":    STMT_KIND_DECSTMT,
	"cot_postinc":    STMT_KIND_INCSTMT,
	"cot_asgbor":     STMT_KIND_ORASSIGNSTMT,
	"cot_asgband":    STMT_KIND_ANDASSIGNSTMT,
	"cot_asgsub":     STMT_KIND_SUBASSIGNSTMT,
	"cot_asgadd":     STMT_KIND_ADDASSIGNSTMT,
	"Switch":         STMT_KIND_EXPRSWITCHSTMT,
	"CaseClauseType": STMT_KIND_CASECLAUSE,
	"Label":          STMT_KIND_LABELEDSTMT,
	"Goto":           STMT_KIND_GOTOSTMT,
}

func GetHexrayStmtKind(e string) int {
	k, err := HexrayStmtKinds[e]
	if !err {
		log.Fatalf("unsupported hexray stmt %s", e)
	}
	return k
}

var HexrayTypeKinds = map[string]int{
	"invalidtype":         0,
	"boolexprtype":        1,
	"inttype":             2,
	"int8type":            3,
	"int16type":           4,
	"int32type":           5,
	"int64type":           6,
	"uinttype":            7,
	"uint8type":           8,
	"uint16type":          9,
	"uint32type":          10,
	"uint64type":          11,
	"uintptrtype":         12,
	"float32type":         13,
	"float64type":         14,
	"complex64type":       15,
	"complex128type":      16,
	"stringexprtype":      17,
	"unsafepointertype":   18,
	"boolliteraltype":     19,
	"intliteraltype":      20,
	"runeliteraltype":     21,
	"floatliteraltype":    22,
	"complexliteraltype":  23,
	"stringliteraltype":   24,
	"nilliteraltype":      25,
	"typeparamtype":       26,
	"arraytype":           27,
	"slicetype":           28,
	"structtype":          29,
	"pointertype":         30,
	"interfacetype":       31,
	"tupletype":           32,
	"signaturetype":       33,
	"maptype":             34,
	"sendchantype":        35,
	"recvchantype":        36,
	"sendrcvchantype":     37,
	"namedtype":           38,
	"typesetliteraltype;": 39,
}

func GetTypeKind(e string) int {
	k, err := HexrayTypeKinds[e]
	if !err {
		log.Fatalf("unsupported hexray stmt %s", e)
	}
	return k
}

// StmtKind is a case type for distinguishing different kinds of statement AST nodes
var StmtKind = NewCaseType(StmtType, "kind")

// BadStmtType is the type of bad (that is, unparseable) statement AST nodes
var BadStmtType = StmtKind.NewBranch("@badstmt")

// DeclStmtType is the type of declaration statement AST nodes
var DeclStmtType = StmtKind.NewBranch("@declstmt", DeclParentType)

// EmptyStmtType is the type of empty statement AST nodes
var EmptyStmtType = StmtKind.NewBranch("@emptystmt")

// LabeledStmtType is the type of labeled statement AST nodes
var LabeledStmtType = StmtKind.NewBranch("@labeledstmt")

// ExprStmtType is the type of expressio statemement AST nodes
var ExprStmtType = StmtKind.NewBranch("@exprstmt")

// SendStmtType is the type of send statement AST nodes
var SendStmtType = StmtKind.NewBranch("@sendstmt")

// IncDecStmtType is the type of increment/decrement statement AST nodes
var IncDecStmtType = NewUnionType("@incdecstmt")

// IncStmtType is the type of increment statement AST nodes
var IncStmtType = StmtKind.NewBranch("@incstmt", IncDecStmtType)

// DecStmtType is the type of decrement statement AST nodes
var DecStmtType = StmtKind.NewBranch("@decstmt", IncDecStmtType)

// AssignmentType is the type of assignment statement AST nodes
var AssignmentType = NewUnionType("@assignment")

// SimpleAssignStmtType is the type of simple (i.e., non-compound) assignment statement AST nodes
var SimpleAssignStmtType = NewUnionType("@simpleassignstmt", AssignmentType)

// CompoundAssignStmtType is the type of compound assignment statement AST nodes
var CompoundAssignStmtType = NewUnionType("@compoundassignstmt", AssignmentType)

// GoStmtType is the type of go statement AST nodes
var GoStmtType = StmtKind.NewBranch("@gostmt")

// DeferStmtType is the type of defer statement AST nodes
var DeferStmtType = StmtKind.NewBranch("@deferstmt")

// ReturnStmtType is the type of return statement AST nodes
var ReturnStmtType = StmtKind.NewBranch("@returnstmt")

// BranchStmtType is the type of branch statement AST nodes
var BranchStmtType = NewUnionType("@branchstmt")

// BreakStmtType is the type of break statement AST nodes
var BreakStmtType = StmtKind.NewBranch("@breakstmt", BranchStmtType)

// ContinueStmtType is the type of continue statement AST nodes
var ContinueStmtType = StmtKind.NewBranch("@continuestmt", BranchStmtType)

// GotoStmtType is the type of goto statement AST nodes
var GotoStmtType = StmtKind.NewBranch("@gotostmt", BranchStmtType)

// FallthroughStmtType is the type of fallthrough statement AST nodes
var FallthroughStmtType = StmtKind.NewBranch("@fallthroughstmt", BranchStmtType)

// BlockStmtType is the type of block statement AST nodes
var BlockStmtType = StmtKind.NewBranch("@blockstmt", ScopeNodeType)

// IfStmtType is the type of if statement AST nodes
var IfStmtType = StmtKind.NewBranch("@ifstmt", ScopeNodeType)

// CaseClauseType is the type of case clause AST nodes
var CaseClauseType = StmtKind.NewBranch("@caseclause", ScopeNodeType)

// SwitchStmtType is the type of switch statement AST nodes, covering both expression switch and type switch
var SwitchStmtType = NewUnionType("@switchstmt", ScopeNodeType)

// ExprSwitchStmtType is the type of expression-switch statement AST nodes
var ExprSwitchStmtType = StmtKind.NewBranch("@exprswitchstmt", SwitchStmtType)

// TypeSwitchStmtType is the type of type-switch statement AST nodes
var TypeSwitchStmtType = StmtKind.NewBranch("@typeswitchstmt", SwitchStmtType)

// CommClauseType is the type of comm clause AST ndoes
var CommClauseType = StmtKind.NewBranch("@commclause", ScopeNodeType)

// SelectStmtType is the type of select statement AST nodes
var SelectStmtType = StmtKind.NewBranch("@selectstmt")

// LoopStmtType is the type of loop statement AST nodes (including for statements and range statements)
var LoopStmtType = NewUnionType("@loopstmt", ScopeNodeType)

// ForStmtType is the type of for statement AST nodes
var ForStmtType = StmtKind.NewBranch("@forstmt", LoopStmtType)

// RangeStmtType is the type of range statement AST nodes
var RangeStmtType = StmtKind.NewBranch("@rangestmt", LoopStmtType)

// AssignStmtTypes is a map from assignmnt operator tokens to corresponding AST node types
var AssignStmtTypes = map[string]*BranchType{
	"cot_asg": StmtKind.NewBranch("@assignstmt", SimpleAssignStmtType),
	//token.DEFINE:         StmtKind.NewBranch("@definestmt", SimpleAssignStmtType),
	//token.ADD_ASSIGN:     StmtKind.NewBranch("@addassignstmt", CompoundAssignStmtType),
	//token.SUB_ASSIGN:     StmtKind.NewBranch("@subassignstmt", CompoundAssignStmtType),
	//token.MUL_ASSIGN:     StmtKind.NewBranch("@mulassignstmt", CompoundAssignStmtType),
	//token.QUO_ASSIGN:     StmtKind.NewBranch("@quoassignstmt", CompoundAssignStmtType),
	//token.REM_ASSIGN:     StmtKind.NewBranch("@remassignstmt", CompoundAssignStmtType),
	//token.AND_ASSIGN:     StmtKind.NewBranch("@andassignstmt", CompoundAssignStmtType),
	//token.OR_ASSIGN:      StmtKind.NewBranch("@orassignstmt", CompoundAssignStmtType),
	//token.XOR_ASSIGN:     StmtKind.NewBranch("@xorassignstmt", CompoundAssignStmtType),
	//token.SHL_ASSIGN:     StmtKind.NewBranch("@shlassignstmt", CompoundAssignStmtType),
	//token.SHR_ASSIGN:     StmtKind.NewBranch("@shrassignstmt", CompoundAssignStmtType),
	//token.AND_NOT_ASSIGN: StmtKind.NewBranch("@andnotassignstmt", CompoundAssignStmtType),
}

// DeclKind is a case type for distinguishing different kinds of declaration AST nodes
var DeclKind = NewCaseType(DeclType, "kind")

// BadDeclType is the type of bad (that is, unparseable) declaration AST nodes
var BadDeclType = DeclKind.NewBranch("@baddecl")

// GenDeclType is the type of generic declaration AST nodes
var GenDeclType = NewUnionType("@gendecl", DocumentableType)

// ImportDeclType is the type of import declaration AST nodes
var ImportDeclType = DeclKind.NewBranch("@importdecl", GenDeclType)

// ConstDeclType is the type of constant declaration AST nodes
var ConstDeclType = DeclKind.NewBranch("@constdecl", GenDeclType)

// TypeDeclType is the type of type declaration AST nodes
var TypeDeclType = DeclKind.NewBranch("@typedecl", GenDeclType)

// VarDeclType is the type of variable declaration AST nodes
var VarDeclType = DeclKind.NewBranch("@vardecl", GenDeclType)

// FuncDeclType is the type of function declaration AST nodes
var FuncDeclType = DeclKind.NewBranch("@funcdecl", DocumentableType, FuncDefType, TypeParamDeclParentType)

// SpecKind is a case type for distinguishing different kinds of declaration specification nodes
var SpecKind = NewCaseType(SpecType, "kind")

// ImportSpecType is the type of import declaration specification nodes
var ImportSpecType = SpecKind.NewBranch("@importspec")

// ValueSpecType is the type of value declaration specification nodes
var ValueSpecType = SpecKind.NewBranch("@valuespec")

// TypeSpecType is the type of type declaration specification nodes
var TypeSpecType = NewUnionType("@typespec", TypeParamDeclParentType)

// TypeDefSpecType is the type of type declaration specification nodes corresponding to type definitions
var TypeDefSpecType = SpecKind.NewBranch("@typedefspec", TypeSpecType)

// AliasSpecType is the type of type declaration specification nodes corresponding to alias declarations
var AliasSpecType = SpecKind.NewBranch("@aliasspec", TypeSpecType)

// ObjectType is the type of objects (that is, declared entities)
var ObjectType = NewPrimaryKeyType("@object")

// ObjectKind is a case type for distinguishing different kinds of built-in and declared objects
var ObjectKind = NewCaseType(ObjectType, "kind")

// TypeParamParentObjectType is the type of objects that can have type parameters as children
var TypeParamParentObjectType = NewUnionType("@typeparamparentobject")

// DeclObjectType is the type of declared objects
var DeclObjectType = NewUnionType("@declobject")

// BuiltinObjectType is the type of built-in objects
var BuiltinObjectType = NewUnionType("@builtinobject")

// PkgObjectType is the type of imported packages
var PkgObjectType = ObjectKind.NewBranch("@pkgobject")

// TypeObjectType is the type of declared or built-in named types
var TypeObjectType = NewUnionType("@typeobject")

// DeclTypeObjectType is the type of declared named types
var DeclTypeObjectType = ObjectKind.NewBranch("@decltypeobject", TypeObjectType, DeclObjectType, TypeParamParentObjectType)

// BuiltinTypeObjectType is the type of built-in named types
var BuiltinTypeObjectType = ObjectKind.NewBranch("@builtintypeobject", TypeObjectType, BuiltinObjectType)

// ValueObjectType is the type of declared or built-in variables or constants
var ValueObjectType = NewUnionType("@valueobject")

// ConstObjectType is the type of declared or built-in constants
var ConstObjectType = NewUnionType("@constobject", ValueObjectType)

// DeclConstObjectType is the type of declared constants
var DeclConstObjectType = ObjectKind.NewBranch("@declconstobject", ConstObjectType, DeclObjectType)

// BuiltinConstObjectType is the type of built-in constants
var BuiltinConstObjectType = ObjectKind.NewBranch("@builtinconstobject", ConstObjectType, BuiltinObjectType)

// VarObjectType is the type of declared or built-in variables (the latter do not currently exist)
var VarObjectType = NewUnionType("@varobject", ValueObjectType)

// DeclVarObjectType is the type of declared variables including function parameters, results and struct fields
var DeclVarObjectType = ObjectKind.NewBranch("@declvarobject", VarObjectType, DeclObjectType)

// FunctionObjectType is the type of declared or built-in functions
var FunctionObjectType = NewUnionType("@functionobject", ValueObjectType)

// DeclFuncObjectType is the type of declared functions, including (abstract and concrete) methods
var DeclFuncObjectType = ObjectKind.NewBranch("@declfunctionobject", FunctionObjectType, DeclObjectType, TypeParamParentObjectType)

// BuiltinFuncObjectType is the type of built-in functions
var BuiltinFuncObjectType = ObjectKind.NewBranch("@builtinfunctionobject", FunctionObjectType, BuiltinObjectType)

// LabelObjectType is the type of statement labels
var LabelObjectType = ObjectKind.NewBranch("@labelobject")

// ScopeType is the type of scopes
var ScopeType = NewPrimaryKeyType("@scope")

// ScopeKind is a case type for distinguishing different kinds of scopes
var ScopeKind = NewCaseType(ScopeType, "kind")

// UniverseScopeType is the type of the universe scope
var UniverseScopeType = ScopeKind.NewBranch("@universescope")

// PackageScopeType is the type of package scopes
var PackageScopeType = ScopeKind.NewBranch("@packagescope")

// LocalScopeType is the type of local (that is, non-universe, non-package) scopes
var LocalScopeType = ScopeKind.NewBranch("@localscope", LocatableType)

// TypeKind is a case type for distinguishing different kinds of types
var TypeKind = NewCaseType(TypeType, "kind")

// BasicType is the union of all basic types
var BasicType = NewUnionType("@basictype")

// BoolType is the union of the normal and literal bool types
var BoolType = NewUnionType("@booltype", BasicType)

// NumericType is the union of numeric types
var NumericType = NewUnionType("@numerictype", BasicType)

// IntegerType is the union of integer types
var IntegerType = NewUnionType("@integertype", NumericType)

// SignedIntegerType is the union of signed integer types
var SignedIntegerType = NewUnionType("@signedintegertype", IntegerType)

// UnsignedIntegerType is the union of unsigned integer types
var UnsignedIntegerType = NewUnionType("@unsignedintegertype", IntegerType)

// FloatType is the union of floating-point types
var FloatType = NewUnionType("@floattype", NumericType)

// ComplexType is the union of complex types
var ComplexType = NewUnionType("@complextype", NumericType)

// StringType is the union of the normal and literal string types
var StringType = NewUnionType("@stringtype", BasicType)

// LiteralType is the union of literal types
var LiteralType = NewUnionType("@literaltype", BasicType)

// BasicTypes is a map from basic type kinds to the corresponding entity types
var BasicTypes = map[string]*BranchType{
	"bool":    TypeKind.NewBranch("@boolexprtype", BoolType),
	"Unknown": TypeKind.NewBranch("@inttype", SignedIntegerType),
	"Void":    TypeKind.NewBranch("@inttype", SignedIntegerType),
	"Int":     TypeKind.NewBranch("@inttype", SignedIntegerType),
	"Float":   TypeKind.NewBranch("@float64type", FloatType),

	"char":    TypeKind.NewBranch("@int8type", SignedIntegerType),
	"short":   TypeKind.NewBranch("@int16type", SignedIntegerType),
	"int64_t": TypeKind.NewBranch("@int64type", SignedIntegerType),

	"unsigned int":   TypeKind.NewBranch("@uinttype", UnsignedIntegerType),
	"unsigned char":  TypeKind.NewBranch("@uint8type", UnsignedIntegerType),
	"unsigned short": TypeKind.NewBranch("@uint16type", UnsignedIntegerType),
	"uint64_t":       TypeKind.NewBranch("@uint64type", UnsignedIntegerType),
	//gotypes.Float32:        TypeKind.NewBranch("@float32type", FloatType),
	//gotypes.Float64:        TypeKind.NewBranch("@float64type", FloatType),
	//gotypes.Complex64:      TypeKind.NewBranch("@complex64type", ComplexType),
	//gotypes.Complex128:     TypeKind.NewBranch("@complex128type", ComplexType),
	//gotypes.String:         TypeKind.NewBranch("@stringexprtype", StringType),
	//gotypes.UnsafePointer:  TypeKind.NewBranch("@unsafepointertype", BasicType),
	//gotypes.UntypedBool:    TypeKind.NewBranch("@boolliteraltype", LiteralType, BoolType),
	//gotypes.UntypedInt:     TypeKind.NewBranch("@intliteraltype", LiteralType, SignedIntegerType),
	//gotypes.UntypedRune:    TypeKind.NewBranch("@runeliteraltype", LiteralType, SignedIntegerType),
	//gotypes.UntypedFloat:   TypeKind.NewBranch("@floatliteraltype", LiteralType, FloatType),
	//gotypes.UntypedComplex: TypeKind.NewBranch("@complexliteraltype", LiteralType, ComplexType),
	//gotypes.UntypedString:  TypeKind.NewBranch("@stringliteraltype", LiteralType, StringType),
	//gotypes.UntypedNil:     TypeKind.NewBranch("@nilliteraltype", LiteralType),
}

// CompositeType is the type of all composite (that is, non-basic) types
var CompositeType = NewUnionType("@compositetype")

// TypeParamType is the type of type parameter types
var TypeParamType = TypeKind.NewBranch("@typeparamtype", CompositeType)

// ElementContainerType is the type of types that have elements, such as arrays
// and channels
var ElementContainerType = NewUnionType("@containertype", CompositeType)

// ArrayType is the type of array types
var ArrayType = TypeKind.NewBranch("@arraytype", ElementContainerType)

// SliceType is the type of slice types
var SliceType = TypeKind.NewBranch("@slicetype", ElementContainerType)

// StructType is the type of struct types
var StructType = TypeKind.NewBranch("@structtype", CompositeType)

// PointerType is the type of pointer types
var PointerType = TypeKind.NewBranch("@pointertype", CompositeType)

// InterfaceType is the type of interface types
var InterfaceType = TypeKind.NewBranch("@interfacetype", CompositeType)

// TupleType is the type of tuple types
var TupleType = TypeKind.NewBranch("@tupletype", CompositeType)

// SignatureType is the type of signature types
var SignatureType = TypeKind.NewBranch("@signaturetype", CompositeType)

// MapType is the type of map types
var MapType = TypeKind.NewBranch("@maptype", ElementContainerType)

// ChanType is the type of channel types
var ChanType = NewUnionType("@chantype", ElementContainerType)

// ChanTypes is a map from channel type directions to the corresponding type
var ChanTypes = map[gotypes.ChanDir]*BranchType{
	gotypes.SendOnly: TypeKind.NewBranch("@sendchantype", ChanType),
	gotypes.RecvOnly: TypeKind.NewBranch("@recvchantype", ChanType),
	gotypes.SendRecv: TypeKind.NewBranch("@sendrcvchantype", ChanType),
}

// NamedType is the type of named types
var NamedType = TypeKind.NewBranch("@namedtype", CompositeType)

// TypeSetLiteral is the type of type set literals
var TypeSetLiteral = TypeKind.NewBranch("@typesetliteraltype", CompositeType)

// PackageType is the type of packages
var PackageType = NewPrimaryKeyType("@package")

// ModExprType is the type of go.mod expression nodes
var ModExprType = NewPrimaryKeyType("@modexpr", ModExprParentType, DocumentableType)

// ModExprKind is a case type for distinguishing different kinds of go.mod expression nodes
var ModExprKind = NewCaseType(ModExprType, "kind")

// ModCommentBlockType is the type of go.mod comment block AST nodes
var ModCommentBlockType = ModExprKind.NewBranch("@modcommentblock")

// ModLineType is the type of go.mod line AST nodes
var ModLineType = ModExprKind.NewBranch("@modline")

// ModLineBlockType is the type of go.mod line block AST nodes
var ModLineBlockType = ModExprKind.NewBranch("@modlineblock")

// ModLParenType is the type of go.mod line block start AST nodes
var ModLParenType = ModExprKind.NewBranch("@modlparen")

// ModRParenType is the type of go.mod line block end AST nodes
var ModRParenType = ModExprKind.NewBranch("@modrparen")

// ErrorType is the type of frontend errors
var ErrorType = NewPrimaryKeyType("@error")

// ErrorKind is a case type for distinguishing different kinds of frontend errors
var ErrorKind = NewCaseType(ErrorType, "kind")

// ErrorTypes is a map from error kinds to the corresponding type
var ErrorTypes = map[packages.ErrorKind]*BranchType{
	packages.UnknownError: ErrorKind.NewBranch("@unknownerror"),
	packages.ListError:    ErrorKind.NewBranch("@listerror"),
	packages.ParseError:   ErrorKind.NewBranch("@parseerror"),
	packages.TypeError:    ErrorKind.NewBranch("@typeerror"),
}

// ErrorTypes is a map from error kinds to the corresponding tag
var ErrorTags = map[packages.ErrorKind]string{
	packages.UnknownError: "@unknownerror",
	packages.ListError:    "@listerror",
	packages.ParseError:   "@parseerror",
	packages.TypeError:    "@typeerror",
}

// LocationsDefaultTable is the table defining location objects
var LocationsDefaultTable = NewTable("locations_default",
	EntityColumn(LocationDefaultType, "id").Key(),
	EntityColumn(FileType, "file"),
	IntColumn("beginLine"),
	IntColumn("beginColumn"),
	IntColumn("endLine"),
	IntColumn("endColumn"),
)

// NumlinesTable is the table containing LoC information
var NumlinesTable = NewTable("numlines",
	EntityColumn(SourceLineType, "element_id"),
	IntColumn("num_lines"),
	IntColumn("num_code"),
	IntColumn("num_comment"),
)

// FilesTable is the table defining file nodes
var FilesTable = NewTable("files",
	EntityColumn(FileType, "id").Key(),
	StringColumn("name"),
)

// FoldersTable is the table defining folder entities
var FoldersTable = NewTable("folders",
	EntityColumn(FolderType, "id").Key(),
	StringColumn("name"),
)

// ContainerParentTable is the table defining the parent-child relation among container entities
var ContainerParentTable = NewTable("containerparent",
	EntityColumn(ContainerType, "parent"),
	EntityColumn(ContainerType, "child").Unique(),
)

// HasLocationTable is the table associating entities with their locations
var HasLocationTable = NewTable("has_location",
	EntityColumn(LocatableType, "locatable").Unique(),
	EntityColumn(LocationType, "location"),
)

// CommentGroupsTable is the table defining comment group entities
var CommentGroupsTable = NewTable("comment_groups",
	EntityColumn(CommentGroupType, "id").Key(),
	EntityColumn(FileType, "parent"),
	IntColumn("idx"),
).KeySet("parent", "idx")

// CommentsTable is the table defining comment entities
var CommentsTable = NewTable("comments",
	EntityColumn(CommentType, "id").Key(),
	IntColumn("kind"),
	EntityColumn(CommentGroupType, "parent"),
	IntColumn("idx"),
	StringColumn("text"),
)

// DocCommentsTable is the table associating doc comments with the nodes they document
var DocCommentsTable = NewTable("doc_comments",
	EntityColumn(DocumentableType, "node").Unique(),
	EntityColumn(CommentGroupType, "comment"),
)

// ExprsTable is the table defining expression AST nodes
var ExprsTable = NewTable("exprs",
	EntityColumn(ExprType, "id").Key(),
	IntColumn("kind"),
	EntityColumn(ExprParentType, "parent"),
	IntColumn("idx"),
).KeySet("parent", "idx")

// LiteralsTable is the table associating literal expression AST nodes with their values
var LiteralsTable = NewTable("literals",
	EntityColumn(ExprType, "expr").Unique(),
	StringColumn("value"),
	StringColumn("raw"),
)

// ConstValuesTable is the table associating constant expressions with their values
var ConstValuesTable = NewTable("constvalues",
	EntityColumn(ExprType, "expr").Unique(),
	StringColumn("value"),
	StringColumn("exact"),
)

// FieldsTable is the table defining field AST nodes
var FieldsTable = NewTable("fields",
	EntityColumn(FieldType, "id").Key(),
	EntityColumn(FieldParentType, "parent"),
	IntColumn("idx"),
)

// TypeParamDeclsTable is the table defining type param declaration AST nodes
var TypeParamDeclsTable = NewTable("typeparamdecls",
	EntityColumn(TypeParamDeclType, "id").Key(),
	EntityColumn(TypeParamDeclParentType, "parent"),
	IntColumn("idx"),
)

// StmtsTable is the table defining statement AST nodes
var StmtsTable = NewTable("stmts",
	EntityColumn(StmtType, "id").Key(),
	IntColumn("kind"),
	EntityColumn(StmtParentType, "parent"),
	IntColumn("idx"),
).KeySet("parent", "idx")

// DeclsTable is the table defining declaration AST nodes
var DeclsTable = NewTable("decls",
	EntityColumn(DeclType, "id").Key(),
	IntColumn("kind"),
	EntityColumn(DeclParentType, "parent"),
	IntColumn("idx"),
).KeySet("parent", "idx")

// SpecsTable is the table defining declaration specification AST nodes
var SpecsTable = NewTable("specs",
	EntityColumn(SpecType, "id").Key(),
	IntColumn("kind"),
	EntityColumn(GenDeclType, "parent"),
	IntColumn("idx"),
).KeySet("parent", "idx")

// ScopesTable is the table defining scopes
var ScopesTable = NewTable("scopes",
	EntityColumn(ScopeType, "id").Key(),
	IntColumn("kind"),
)

// ScopeNestingTable is the table describing scope nesting
var ScopeNestingTable = NewTable("scopenesting",
	EntityColumn(ScopeType, "inner").Unique(),
	EntityColumn(ScopeType, "outer"),
)

// ScopeNodesTable is the table associating local scopes with the AST nodes that induce them
var ScopeNodesTable = NewTable("scopenodes",
	EntityColumn(ScopeNodeType, "node").Unique(),
	EntityColumn(LocalScopeType, "scope"),
)

// ObjectsTable is the table describing objects (that is, declared entities)
var ObjectsTable = NewTable("objects",
	EntityColumn(ObjectType, "id").Key(),
	IntColumn("kind"),
	StringColumn("name"),
)

// ObjectScopesTable is the table describing the scope to which an object belongs (if any)
var ObjectScopesTable = NewTable("objectscopes",
	EntityColumn(ObjectType, "object").Unique(),
	EntityColumn(ScopeType, "scope"),
)

// ObjectTypesTable is the table describing the type of an object (if any)
var ObjectTypesTable = NewTable("objecttypes",
	EntityColumn(ObjectType, "object").Unique(),
	EntityColumn(TypeType, "tp"),
)

// MethodReceiversTable maps methods to their receiver
var MethodReceiversTable = NewTable("methodreceivers",
	EntityColumn(ObjectType, "method").Unique(),
	EntityColumn(ObjectType, "receiver"),
)

// FieldStructsTable maps fields to the structs they are in
var FieldStructsTable = NewTable("fieldstructs",
	EntityColumn(ObjectType, "field").Unique(),
	EntityColumn(StructType, "struct"),
)

// MethodHostsTable maps interface methods to the named type they belong to
var MethodHostsTable = NewTable("methodhosts",
	EntityColumn(ObjectType, "method"),
	EntityColumn(NamedType, "host"),
)

// DefsTable maps identifiers to the objects they define
var DefsTable = NewTable("defs",
	EntityColumn(IdentExpr, "ident"),
	EntityColumn(ObjectType, "object"),
)

// UsesTable maps identifiers to the objects they denote
var UsesTable = NewTable("uses",
	EntityColumn(IdentExpr, "ident"),
	EntityColumn(ObjectType, "object"),
)

// TypesTable is the table describing types
var TypesTable = NewTable("types",
	EntityColumn(TypeType, "id").Key(),
	IntColumn("kind"),
)

// TypeOfTable is the table associating expressions with their types (if known)
var TypeOfTable = NewTable("type_of",
	EntityColumn(ExprType, "expr").Unique(),
	EntityColumn(TypeType, "tp"),
)

// TypeNameTable is the table associating named types with their names
var TypeNameTable = NewTable("typename",
	EntityColumn(TypeType, "tp").Unique(),
	StringColumn("name"),
)

// KeyTypeTable is the table associating maps with their key type
var KeyTypeTable = NewTable("key_type",
	EntityColumn(MapType, "map").Unique(),
	EntityColumn(TypeType, "tp"),
)

// ElementTypeTable is the table associating container types with their element
// type
var ElementTypeTable = NewTable("element_type",
	EntityColumn(ElementContainerType, "container").Unique(),
	EntityColumn(TypeType, "tp"),
)

// BaseTypeTable is the table associating pointer types with their base type
var BaseTypeTable = NewTable("base_type",
	EntityColumn(PointerType, "ptr").Unique(),
	EntityColumn(TypeType, "tp"),
)

// UnderlyingTypeTable is the table associating named types with their
// underlying type
var UnderlyingTypeTable = NewTable("underlying_type",
	EntityColumn(NamedType, "named").Unique(),
	EntityColumn(TypeType, "tp"),
)

// ComponentTypesTable is the table associating composite types with their component types
var ComponentTypesTable = NewTable("component_types",
	EntityColumn(CompositeType, "parent"),
	IntColumn("index"),
	StringColumn("name"),
	EntityColumn(TypeType, "tp"),
).KeySet("parent", "index")

// ArrayLengthTable is the table associating array types with their length (represented as a string
// since Go array lengths are 64-bit and hence do not always fit into a QL integer)
var ArrayLengthTable = NewTable("array_length",
	EntityColumn(ArrayType, "tp").Unique(),
	StringColumn("len"),
)

// TypeObjectTable maps types to their corresponding objects, if any
var TypeObjectTable = NewTable("type_objects",
	EntityColumn(TypeType, "tp").Unique(),
	EntityColumn(ObjectType, "object"),
)

// PackagesTable is the table describing packages
var PackagesTable = NewTable("packages",
	EntityColumn(PackageType, "id").Key(),
	StringColumn("name"),
	StringColumn("path"),
	EntityColumn(PackageScopeType, "scope"),
)

// ModExprsTable is the table defining expression AST nodes for go.mod files
var ModExprsTable = NewTable("modexprs",
	EntityColumn(ModExprType, "id").Key(),
	IntColumn("kind"),
	EntityColumn(ModExprParentType, "parent"),
	IntColumn("idx"),
).KeySet("parent", "idx")

// ModTokensTable is the table associating go.mod tokens with their Line or LineBlock
var ModTokensTable = NewTable("modtokens",
	StringColumn("token"),
	EntityColumn(ModExprType, "parent"),
	IntColumn("idx"),
).KeySet("parent", "idx")

// ErrorsTable is the table describing frontend errors
var ErrorsTable = NewTable("errors",
	EntityColumn(ErrorType, "id").Key(),
	IntColumn("kind"),
	StringColumn("msg"),
	StringColumn("rawpos"),
	StringColumn("file"),
	IntColumn("line"),
	IntColumn("col"),
	EntityColumn(PackageType, "package"),
	IntColumn("idx"),
).KeySet("package", "idx")

// HasEllipsisTable is the table containing all call expressions that have ellipses
var HasEllipsisTable = NewTable("has_ellipsis",
	EntityColumn(CallOrConversionExpr, "id"),
)

// VariadicTable is the table describing which functions are variadic
var VariadicTable = NewTable("variadic",
	EntityColumn(SignatureType, "id"),
)

// TypeParamTable is the table describing type parameter types
var TypeParamTable = NewTable("typeparam",
	EntityColumn(TypeParamType, "tp").Unique(),
	StringColumn("name"),
	EntityColumn(CompositeType, "bound"),
	EntityColumn(TypeParamParentObjectType, "parent"),
	IntColumn("idx"),
).KeySet("parent", "idx")
