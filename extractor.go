package extractor

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"go/ast"
	"go/constant"
	"go/scanner"
	"go/token"
	"go/types"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/github/codeql-go/extractor/dbscheme"
	"github.com/github/codeql-go/extractor/srcarchive"
	"github.com/github/codeql-go/extractor/trap"
	"github.com/github/codeql-go/extractor/util"
	"golang.org/x/tools/go/packages"
)

var MaxGoRoutines int

func init() {
	// this sets the number of threads that the Go runtime will spawn; this is separate
	// from the number of goroutines that the program spawns, which are scheduled into
	// the system threads by the Go runtime scheduler
	threads := os.Getenv("LGTM_THREADS")
	if maxprocs, err := strconv.Atoi(threads); err == nil && maxprocs > 0 {
		log.Printf("Max threads set to %d", maxprocs)
		runtime.GOMAXPROCS(maxprocs)
	} else if threads != "" {
		log.Printf("Warning: LGTM_THREADS value %s is not valid, defaulting to using all available threads.", threads)
	}
	// if the value is empty or not set, use the Go default, which is the number of cores
	// available since Go 1.5, but is subject to change

	var err error
	if MaxGoRoutines, err = strconv.Atoi(util.Getenv(
		"CODEQL_EXTRACTOR_GO_MAX_GOROUTINES",
		"SEMMLE_MAX_GOROUTINES",
	)); err != nil {
		MaxGoRoutines = 32
	} else {
		log.Printf("Max goroutines set to %d", MaxGoRoutines)
	}
}

// ExtractWithFlags extracts the packages specified by the given patterns and build flags
func ExtractWithFlags(astfile string, asttypefile string) error {
	startTime := time.Now()

	extraction := NewExtraction(astfile)
	defer extraction.StatWriter.Close()

	extraction.extractPackage(astfile, asttypefile)

	extraction.WaitGroup.Wait()

	log.Println("Done extracting packages.")

	t := time.Now()
	elapsed := t.Sub(startTime)
	dbscheme.CompilationFinishedTable.Emit(extraction.StatWriter, extraction.Label, 0.0, elapsed.Seconds())

	return nil
}

type Extraction struct {
	// A lock for preventing concurrent writes to maps and the stat trap writer, as they are not
	// thread-safe
	Lock         sync.Mutex
	LabelKey     string
	Label        trap.Label
	StatWriter   *trap.Writer
	WaitGroup    sync.WaitGroup
	GoroutineSem *semaphore
	FdSem        *semaphore
	NextFileId   int
	FileInfo     map[string]*FileInfo
	SeenGoMods   map[string]bool
}

type FileInfo struct {
	Idx     int
	NextErr int
}

func (extraction *Extraction) SeenFile(path string) bool {
	_, ok := extraction.FileInfo[path]
	return ok
}

func (extraction *Extraction) GetFileInfo(path string) *FileInfo {
	if fileInfo, ok := extraction.FileInfo[path]; ok {
		return fileInfo
	}

	extraction.FileInfo[path] = &FileInfo{extraction.NextFileId, 0}
	extraction.NextFileId += 1

	return extraction.FileInfo[path]
}

func (extraction *Extraction) GetFileIdx(path string) int {
	return extraction.GetFileInfo(path).Idx
}

func (extraction *Extraction) GetNextErr(path string) int {
	finfo := extraction.GetFileInfo(path)
	res := finfo.NextErr
	finfo.NextErr += 1
	return res
}

func NewExtraction(astfile string) *Extraction {
	hash := md5.New()
	io.WriteString(hash, "go")
	io.WriteString(hash, astfile)
	io.WriteString(hash, " --")

	sum := hash.Sum(nil)

	i := 0
	var path string
	// split compilation files into directories to avoid filling a single directory with too many files
	pathFmt := fmt.Sprintf("compilations/%s/%s_%%d", hex.EncodeToString(sum[:1]), hex.EncodeToString(sum[1:]))
	for {
		path = fmt.Sprintf(pathFmt, i)
		file, err := trap.FileFor(path)
		if err != nil {
			log.Fatalf("Error creating trap file: %s\n", err.Error())
		}
		i++

		if !util.FileExists(file) {
			break
		}
	}

	statWriter, err := trap.NewWriter(path)
	if err != nil {
		log.Fatal(err)
	}
	lblKey := fmt.Sprintf("%s_%d;compilation", hex.EncodeToString(sum), i)
	lbl := statWriter.Labeler.GlobalID(lblKey)

	wd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Unable to determine current directory: %s\n", err.Error())
	}

	dbscheme.CompilationsTable.Emit(statWriter, lbl, wd)
	i = 0
	extractorPath, err := util.GetExtractorPath()
	if err != nil {
		log.Fatalf("Unable to get extractor path: %s\n", err.Error())
	}
	dbscheme.CompilationArgsTable.Emit(statWriter, lbl, 0, extractorPath)
	i++

	// emit a fake "--" argument to make it clear that what comes after it are patterns
	dbscheme.CompilationArgsTable.Emit(statWriter, lbl, i, "--")
	i++

	return &Extraction{
		LabelKey:   lblKey,
		Label:      lbl,
		StatWriter: statWriter,
		// this semaphore is used to limit the number of files that are open at once;
		// this is to prevent the extractor from running into issues with caps on the
		// number of open files that can be held by one process
		FdSem: newSemaphore(100),
		// this semaphore is used to limit the number of goroutines spawned, so we
		// don't run into memory issues
		GoroutineSem: newSemaphore(MaxGoRoutines),
		NextFileId:   0,
		FileInfo:     make(map[string]*FileInfo),
		SeenGoMods:   make(map[string]bool),
	}
}

// extractObject extracts a single object and emits it to the objects table.
// For more information on objects, see:
// https://github.com/golang/example/blob/master/gotypes/README.md#objects
func extractObject(tw *trap.Writer, name string, typ string, lbl trap.Label) {
	isBuiltin := false
	var kind int
	switch typ {

	case "TypeName":
		if isBuiltin {
			kind = dbscheme.BuiltinTypeObjectType.Index()
		} else {
			kind = dbscheme.DeclTypeObjectType.Index()
		}
	case "Const":
		if isBuiltin {
			kind = dbscheme.BuiltinConstObjectType.Index()
		} else {
			kind = dbscheme.DeclConstObjectType.Index()
		}
	case "Var":
		kind = dbscheme.DeclVarObjectType.Index()
	case "Func":
		kind = dbscheme.DeclFuncObjectType.Index()
	case "Label":
		kind = dbscheme.LabelObjectType.Index()
	default:
		log.Fatalf("unknown object of type %v", typ)
	}
	dbscheme.ObjectsTable.Emit(tw, lbl, kind, name)
}

// emitObjectType emits the type information for a given object
func emitObjectType(tw *trap.Writer, tp string, lbl trap.Label) {
	dbscheme.ObjectTypesTable.Emit(tw, lbl, tw.Labeler.LabelToTypeLabel(lbl.String()))
}

var (
	// file:line:col
	threePartPos = regexp.MustCompile(`^(.+):(\d+):(\d+)$`)
	// file:line
	twoPartPos = regexp.MustCompile(`^(.+):(\d+)$`)
)

// extractError extracts the message and location of a frontend error
func (extraction *Extraction) extractError(tw *trap.Writer, err packages.Error, pkglbl trap.Label, idx int) {
	var (
		lbl       = tw.Labeler.FreshID()
		tag       = dbscheme.ErrorTags[err.Kind]
		kind      = dbscheme.ErrorTypes[err.Kind].Index()
		pos       = err.Pos
		file      = ""
		line, col int
		e         error
	)

	if pos == "" || pos == "-" {
		// extract a dummy file
		wd, e := os.Getwd()
		if e != nil {
			wd = "."
			log.Printf("Warning: failed to get working directory")
		}
		ewd, e := filepath.EvalSymlinks(wd)
		if e != nil {
			ewd = wd
			log.Printf("Warning: failed to evaluate symlinks for %s", wd)
		}
		file = filepath.Join(ewd, "-")
		extraction.extractFileInfo(tw, file, true)
	} else {
		var rawfile string
		if parts := threePartPos.FindStringSubmatch(pos); parts != nil {
			// "file:line:col"
			col, e = strconv.Atoi(parts[3])
			if e != nil {
				log.Printf("Warning: malformed column number `%s`: %v", parts[3], e)
			}
			line, e = strconv.Atoi(parts[2])
			if e != nil {
				log.Printf("Warning: malformed line number `%s`: %v", parts[2], e)
			}
			rawfile = parts[1]
		} else if parts := twoPartPos.FindStringSubmatch(pos); parts != nil {
			// "file:line"
			line, e = strconv.Atoi(parts[2])
			if e != nil {
				log.Printf("Warning: malformed line number `%s`: %v", parts[2], e)
			}
			rawfile = parts[1]
		} else if pos != "" && pos != "-" {
			log.Printf("Warning: malformed error position `%s`", pos)
		}
		afile, e := filepath.Abs(rawfile)
		if e != nil {
			log.Printf("Warning: failed to get absolute path for for %s", file)
			afile = file
		}
		file, e = filepath.EvalSymlinks(afile)
		if e != nil {
			log.Printf("Warning: failed to evaluate symlinks for %s", afile)
			file = afile
		}

		extraction.extractFileInfo(tw, file, false)
	}

	extraction.Lock.Lock()
	flbl := extraction.StatWriter.Labeler.FileLabelFor(file)
	diagLbl := extraction.StatWriter.Labeler.FreshID()
	dbscheme.DiagnosticsTable.Emit(
		extraction.StatWriter, diagLbl, 1, tag, err.Msg, err.Msg,
		emitLocation(extraction.StatWriter, flbl, line, col, line, col))
	dbscheme.DiagnosticForTable.Emit(extraction.StatWriter, diagLbl, extraction.Label, extraction.GetFileIdx(file), extraction.GetNextErr(file))
	extraction.Lock.Unlock()
	transformed := filepath.ToSlash(srcarchive.TransformPath(file))
	dbscheme.ErrorsTable.Emit(tw, lbl, kind, err.Msg, pos, transformed, line, col, pkglbl, idx)
}

// extractPackage extracts AST information for all files in the given package
func (extraction *Extraction) extractPackage(file string, typefile string) {
	extraction.WaitGroup.Add(1)
	extraction.GoroutineSem.acquire(1)
	go func(astFile string, astTypeFile string) {
		err := extraction.extractFile(astFile, astTypeFile)
		if err != nil {
			log.Fatal(err)
		}
		extraction.GoroutineSem.release(1)
		extraction.WaitGroup.Done()
	}(file, typefile)
}

// normalizedPath computes the normalized path (with symlinks resolved) for the given file
func normalizedPath(ast *ast.File, fset *token.FileSet) string {
	file := fset.File(ast.Package).Name()
	path, err := filepath.EvalSymlinks(file)
	if err != nil {
		return file
	}
	return path
}

// extractFile extracts AST information for the given file
func (extraction *Extraction) extractFile(astFile string, astTypeFile string) error {
	extraction.FdSem.acquire(3)

	log.Printf("Extracting %s", astFile)
	start := time.Now()

	defer extraction.FdSem.release(1)

	tw, err := trap.NewWriter(astFile)
	if err != nil {
		extraction.FdSem.release(2)
		return err
	}
	defer tw.Close()

	err = srcarchive.Add(astFile)
	extraction.FdSem.release(2)
	if err != nil {
		return err
	}

	extraction.extractFileInfo(tw, astFile, false)

	extractFileNode(tw, astFile, astTypeFile)

	//extractObjectTypes(tw, astFile
	tw.ForEachObject(emitObjectType)
	end := time.Since(start)
	log.Printf("Done extracting %s (%dms)", astFile, end.Nanoseconds()/1000000)

	return nil
}

// extractFileInfo extracts file-system level information for the given file, populating
// the `files` and `containerparent` tables
func (extraction *Extraction) extractFileInfo(tw *trap.Writer, file string, isDummy bool) {
	// We may visit the same file twice because `extractError` calls this function to describe files containing
	// compilation errors. It is also called for user source files being extracted.
	extraction.Lock.Lock()
	if extraction.SeenFile(file) {
		extraction.Lock.Unlock()
		return
	}
	extraction.Lock.Unlock()

	path := filepath.ToSlash(srcarchive.TransformPath(file))
	components := strings.Split(path, "/")
	parentPath := ""
	var parentLbl trap.Label

	for i, component := range components {
		if i == 0 {
			if component == "" {
				path = "/"
			} else {
				path = component
			}
		} else {
			path = parentPath + "/" + component
		}
		if i == len(components)-1 {
			lbl := tw.Labeler.FileLabelFor(file)
			dbscheme.FilesTable.Emit(tw, lbl, path)
			dbscheme.ContainerParentTable.Emit(tw, parentLbl, lbl)
			dbscheme.HasLocationTable.Emit(tw, lbl, emitLocation(tw, lbl, 0, 0, 0, 0))
			extraction.Lock.Lock()
			slbl := extraction.StatWriter.Labeler.FileLabelFor(file)
			if !isDummy {
				dbscheme.CompilationCompilingFilesTable.Emit(extraction.StatWriter, extraction.Label, extraction.GetFileIdx(file), slbl)
			}
			extraction.Lock.Unlock()
			break
		}
		lbl := tw.Labeler.GlobalID(util.EscapeTrapSpecialChars(path) + ";folder")
		dbscheme.FoldersTable.Emit(tw, lbl, path)
		if i > 0 {
			dbscheme.ContainerParentTable.Emit(tw, parentLbl, lbl)
		}
		if path != "/" {
			parentPath = path
		}
		parentLbl = lbl
	}
}

// extractLocation emits a location entity for the given entity
func extractLocation(tw *trap.Writer, entity trap.Label, sl int, sc int, el int, ec int) {
	filelbl := tw.Labeler.FileLabel()
	dbscheme.HasLocationTable.Emit(tw, entity, emitLocation(tw, filelbl, sl, sc, el, ec))
}

// emitLocation emits a location entity
func emitLocation(tw *trap.Writer, filelbl trap.Label, sl int, sc int, el int, ec int) trap.Label {
	locLbl := tw.Labeler.GlobalID(fmt.Sprintf("loc,{%s},%d,%d,%d,%d", filelbl, sl, sc, el, ec))
	dbscheme.LocationsDefaultTable.Emit(tw, locLbl, filelbl, sl, sc, el, ec)

	return locLbl
}

// extractNodeLocation extracts location information for the given node
func extractNodeLocation(tw *trap.Writer, nd gjson.Result, lbl trap.Label) {
	if !nd.Get("attributes").Exists() {
		return
	}
	attr := nd.Get("attributes")
	ea := int(attr.Get("ea").Int())
	treeidx := int(attr.Get("treeindex").Int())
	extractLocation(tw, lbl, ea, treeidx, ea, treeidx)
}

// extractScopeLocation extracts location information for the given scope
func extractScopeLocation(tw *trap.Writer, scope gjson.Result, lbl trap.Label) {
	extractNodeLocation(tw, scope, lbl)
}

func parseJsonFile(fpath string) gjson.Result {
	data, erx := os.ReadFile(fpath)
	if erx != nil {
		log.Fatal("read file failed, err:", erx)
		return gjson.Result{}
	}

	value := gjson.Parse(string(data))
	return value
}

func dupExpr(expr gjson.Result) gjson.Result {
	r := gjson.Parse(expr.Raw)
	return r
}

func extractFunctionType(tw *trap.Writer, expr gjson.Result, parent trap.Label, idx int) {
	lbl := tw.Labeler.LocalIDWithPad(expr, "_functypeexpr", true)
	var kind int
	kind = dbscheme.FuncTypeExpr.Index()
	extractFields(tw, expr.Get("paramters").Array(), lbl, 0, 1)
	extractReturnType(tw, lbl, expr.Get("returnType").String())
	dbscheme.ExprsTable.Emit(tw, lbl, kind, parent, idx)
	extractNodeLocation(tw, expr, lbl)
}

func emitLocalDecl(tw *trap.Writer, nd gjson.Result, parent trap.Label, idx int) {
	lbl := tw.Labeler.LocalID(nd, true)
	var kind int

	extractTypeOf(tw, nd, lbl)
	kind = dbscheme.VarDeclType.Index()

	dbscheme.DeclsTable.Emit(tw, lbl, kind, parent, idx)
	extractNodeLocation(tw, nd, lbl)
}

func readDecl(tw *trap.Writer, stmt gjson.Result, parent trap.Label, idx int) {

	lbl := tw.Labeler.LocalIDWithPad(stmt, "_readDecl", true)
	var kind int
	nodeType := stmt.Get("nodeType").String()

	attributes := stmt.Get("attributes")

	switch nodeType {
	case "Function":
		kind = dbscheme.FuncDeclType.Index()
		functionName := stmt.Get("name").String()

		scopeLabel := tw.Labeler.ScopeID(functionName, "")
		dbscheme.ScopesTable.Emit(tw, scopeLabel, dbscheme.LocalScopeType.Index())
		extractScopeLocation(tw, stmt, scopeLabel)

		tw.Labeler.SetScope(functionName)
		siglbl := tw.Labeler.LookupFunctionSignature(functionName)

		emitFuncExpr(tw, attributes, lbl, 0, functionName, siglbl)
		//extractParams(tw, stmt, lbl, 1)

		extractFunctionType(tw, stmt, lbl, 1)

		localDecls := stmt.Get("localDecls").Array()

		blockStmt := stmt.Get("body").Array()[0]

		{
			blockLbl := tw.Labeler.LocalIDWithPad(stmt, "_stmt_Block", true)
			blockKind := dbscheme.BlockStmtType.Index()
			xid := 0
			{

				for _, localDecl := range localDecls {
					declLbl := tw.Labeler.LocalIDWithPad(stmt, fmt.Sprintf("%d_vardeclstmt", xid), true)
					declKind := dbscheme.DeclStmtType.Index()
					specKind := dbscheme.ValueSpecType.Index()
					specLbl := tw.Labeler.LocalIDWithPad(localDecl, "_speclbl", true)

					varDeclLbl := tw.Labeler.LocalIDWithPad(stmt, localDecl.Get("name").String()+"_vardecllbl", true)

					emitIdentExpr(tw, localDecl.Get("attributes"), specLbl, -1, localDecl.Get("name").String(), localDecl.Get("type").String(), true)
					emitTypeExpr(tw, localDecl.Get("attributes"), specLbl, 0, localDecl.Get("type").String(), localDecl.Get("type").String(), false)

					dbscheme.SpecsTable.Emit(tw, specLbl, specKind, varDeclLbl, 0)
					extractNodeLocation(tw, localDecl, specLbl)

					dbscheme.DeclsTable.Emit(tw, varDeclLbl, 4, declLbl, 0) //vardecl
					extractNodeLocation(tw, localDecl, varDeclLbl)

					dbscheme.StmtsTable.Emit(tw, declLbl, declKind, blockLbl, xid)
					extractNodeLocation(tw, localDecl, declLbl)
					xid += 1
				}

			}

			extractStmts(tw, blockStmt.Get("stmts").Array(), blockLbl, xid, 1)

			dbscheme.StmtsTable.Emit(tw, blockLbl, blockKind, lbl, 2)
			extractNodeLocation(tw, blockStmt, blockLbl)

		}

		tw.Labeler.ResetScope()
	default:
		log.Fatalf("unknown declaration of type %T", stmt.String())
	}

	dbscheme.DeclsTable.Emit(tw, lbl, kind, parent, idx)
	extractNodeLocation(tw, stmt, lbl)
}

func loadTypeDecls(tw *trap.Writer, types_file string) {
	var typeMap map[string]gjson.Result = make(map[string]gjson.Result)
	types := parseJsonFile(types_file).Array()

	for i := 0; i < len(types); i++ {
		tp := types[i]
		name := tp.Get("name").String()
		typeMap[name] = tp
	}

	for i := 0; i < len(types); i++ {
		typ := types[i]
		extractType(tw, typeMap, typ)
	}
}

// extractFileNode extracts AST information for the given file and all nodes contained in it
func extractFileNode(tw *trap.Writer, astfile string, astTypeFile string) {
	lbl := tw.Labeler.FileLabel()

	loadTypeDecls(tw, astTypeFile)

	asts := parseJsonFile(astfile).Array()

	for i := 0; i < len(asts); i++ {
		ast := asts[i]
		readDecl(tw, ast, lbl, i)
	}
}

// emitScopeNodeInfo associates an AST node with its induced scope, if any
func emitScopeNodeInfo(tw *trap.Writer, nd gjson.Result, lbl trap.Label) {
	dbscheme.ScopeNodesTable.Emit(tw, lbl, tw.Labeler.ScopeID(tw.Labeler.GetCurrentScope()+"_"+lbl.String(), ""))
}

func emitFuncExpr(tw *trap.Writer, attributes gjson.Result, parent trap.Label, idx int, name string, siglbl trap.Label) {
	ea := attributes.Get("ea").String()
	treeindex := attributes.Get("treeindex").String()

	x := fmt.Sprintf("{\"nodeType\": \"Identifier\",\"attributes\": {  \"ea\": \"%s\",  \"treeindex\": \"%s\"},\"name\": \"%s\",\"code\": \"Func_%s\"}", ea, treeindex, name, name)

	expr := gjson.Parse(x)

	lbl := tw.Labeler.LocalID(expr, false)
	kind := dbscheme.IdentExpr.Index()

	{
		tw.Labeler.SetLabelToTypeLabel(lbl.String(), siglbl)
		dbscheme.TypeOfTable.Emit(tw, lbl, siglbl)
	}

	dbscheme.LiteralsTable.Emit(tw, lbl, name, name)

	useTyp, _ := lookupTypeLabel(tw, "int")
	objlbl, exists := tw.Labeler.LookupObjectIDWithoutScope(expr, useTyp, false)
	if objlbl == trap.InvalidLabel {
		log.Printf("Omitting use binding to unknown object %v", name)
	} else {
		if !exists {
			extractObject(tw, name, "Func", objlbl)
		}

		tw.Labeler.SetLabelToTypeLabel(objlbl.String(), siglbl)
		dbscheme.DefsTable.Emit(tw, lbl, objlbl)
	}

	dbscheme.ExprsTable.Emit(tw, lbl, kind, parent, idx)
	extractNodeLocation(tw, expr, lbl)
}

func emitIdentExpr(tw *trap.Writer, attributes gjson.Result, parent trap.Label, idx int, name string, typ string, isDef bool) {
	ea := attributes.Get("ea").String()
	treeindex := attributes.Get("treeindex").String()
	x := fmt.Sprintf("{\"nodeType\": \"Identifier\",\"attributes\": "+
		"{  \"ea\": \"%s\",  \"treeindex\": \"%s\"},"+
		"\"name\": \"%s\",\"code\": \"%s\","+
		"\"type\": \"%s\"}", ea, treeindex, name, name, typ)

	expr := gjson.Parse(x)
	lbl := tw.Labeler.LocalID(expr, true)
	extractTypeOf(tw, expr, lbl)

	kind := dbscheme.IdentExpr.Index()
	dbscheme.LiteralsTable.Emit(tw, lbl, name, name)

	useTyp, _ := lookupTypeLabel(tw, typ)
	objlbl, exists := tw.Labeler.LookupObjectID(expr, useTyp, false)
	if objlbl == trap.InvalidLabel {
		log.Printf("Omitting use binding to unknown object %v", name)
	} else {
		if !exists {
			extractObject(tw, name, "Var", objlbl)
			scopeLabel := tw.Labeler.GetCurrentScopeLabel()
			dbscheme.ObjectScopesTable.Emit(tw, objlbl, scopeLabel)
			tw.Labeler.SetLabelToTypeLabel(objlbl.String(), useTyp)

		}

		if isDef {
			dbscheme.DefsTable.Emit(tw, lbl, objlbl)
		} else {
			dbscheme.UsesTable.Emit(tw, lbl, objlbl)
		}
	}

	dbscheme.ExprsTable.Emit(tw, lbl, kind, parent, idx)
	extractNodeLocation(tw, expr, lbl)
}

func emitTypeExpr(tw *trap.Writer, attributes gjson.Result, parent trap.Label, idx int, name string, typ string, isDef bool) {
	ea := attributes.Get("ea").String()
	treeindex := attributes.Get("treeindex").String()
	x := fmt.Sprintf("{\"nodeType\": \"Identifier\",\"attributes\": "+
		"{  \"ea\": \"%s\",  \"treeindex\": \"%s\"},"+
		"\"name\": \"%s\",\"code\": \"%s\","+
		"\"type\": \"%s\"}", ea, treeindex, name, name, typ)

	expr := gjson.Parse(x)
	lbl := tw.Labeler.LocalID(expr, true)
	extractTypeOf(tw, expr, lbl)

	kind := dbscheme.IdentExpr.Index()
	dbscheme.LiteralsTable.Emit(tw, lbl, name, name)

	useTyp, _ := lookupTypeLabel(tw, typ)
	objlbl, exists := tw.Labeler.LookupObjectIDWithoutScope(expr, useTyp, false)
	if objlbl == trap.InvalidLabel {
		log.Printf("Omitting use binding to unknown object %v", name)
	} else {
		if !exists {
			extractObject(tw, name, "TypeName", objlbl)
			//scopeLabel := tw.Labeler.GetCurrentScopeLabel()
			//dbscheme.ObjectScopesTable.Emit(tw, objlbl, scopeLabel)
			tw.Labeler.SetLabelToTypeLabel(objlbl.String(), useTyp)
		}

		if isDef {
			dbscheme.DefsTable.Emit(tw, lbl, objlbl)
		} else {
			dbscheme.UsesTable.Emit(tw, lbl, objlbl)
		}
	}

	dbscheme.ExprsTable.Emit(tw, lbl, kind, parent, idx)
	extractNodeLocation(tw, expr, lbl)
}

func emitFunctionName(tw *trap.Writer, expr gjson.Result, parent trap.Label, idx int, skipExtractingValue bool) bool {
	lbl := tw.Labeler.LocalID(expr, true)
	//extractTypeOf(tw, expr, lbl)

	var kind int
	var name string

	nodeType := expr.Get("nodeType").String()
	switch nodeType {
	case "Identifier":
		kind = dbscheme.IdentExpr.Index()
		name = expr.Get("name").String()
	default:
		kind = dbscheme.IdentExpr.Index()
		name = expr.Get("name").String()
	}

	typ := expr.Get("type").String()
	tplbl := tw.Labeler.LookupFunctionSignature(name)

	{
		tw.Labeler.SetLabelToTypeLabel(lbl.String(), tplbl)
		dbscheme.TypeOfTable.Emit(tw, lbl, tplbl)
	}

	dbscheme.LiteralsTable.Emit(tw, lbl, name, name)
	useTyp, _ := lookupTypeLabel(tw, typ)
	objlbl, exists := tw.Labeler.LookupObjectIDWithoutScope(expr, useTyp, false)
	if objlbl == trap.InvalidLabel {
		log.Printf("Omitting use binding to unknown object %v", expr.String())
	} else {
		if !exists {
			extractObject(tw, name, "Func", objlbl)
			tw.Labeler.SetLabelToTypeLabel(objlbl.String(), tplbl)

		}
		dbscheme.UsesTable.Emit(tw, lbl, objlbl)
	}
	dbscheme.ExprsTable.Emit(tw, lbl, kind, parent, idx)
	extractNodeLocation(tw, expr, lbl)
	return true
}

func emitHelperFunctionName(tw *trap.Writer, expr gjson.Result, helper_name string, parent trap.Label, idx int) bool {
	lbl := tw.Labeler.LocalIDWithPad(expr, "_helper_label", true)
	//extractTypeOf(tw, expr, lbl)

	var kind int

	kind = dbscheme.IdentExpr.Index()
	name := helper_name
	tplbl := tw.Labeler.LookupFunctionSignature(name)

	{
		tw.Labeler.SetLabelToTypeLabel(lbl.String(), tplbl)
		dbscheme.TypeOfTable.Emit(tw, lbl, tplbl)
	}

	dbscheme.LiteralsTable.Emit(tw, lbl, name, name)
	useTyp, _ := lookupTypeLabel(tw, "int")

	x := fmt.Sprintf("{\"name\": \"%s\"}", name)

	fobj := gjson.Parse(x)

	objlbl, exists := tw.Labeler.LookupObjectIDWithoutScope(fobj, useTyp, false)
	if objlbl == trap.InvalidLabel {
		log.Printf("Omitting use binding to unknown object %v", fobj.String())
	} else {
		if !exists {
			extractObject(tw, name, "Func", objlbl)
			tw.Labeler.SetLabelToTypeLabel(objlbl.String(), tplbl)

		}
		dbscheme.UsesTable.Emit(tw, lbl, objlbl)
	}

	dbscheme.ExprsTable.Emit(tw, lbl, kind, parent, idx)
	extractNodeLocation(tw, expr, lbl)
	return true
}

// extractExpr extracts AST information for the given expression and all its subexpressions
func extractExpr(tw *trap.Writer, expr gjson.Result, parent trap.Label, idx int, skipExtractingValue bool) {
	nodeType := expr.Get("nodeType").String()
	lbl := tw.Labeler.LocalIDWithPad(expr, nodeType, true)
	extractTypeOf(tw, expr, lbl)

	attributes := expr.Get("attributes")
	var kind int

	switch nodeType {

	case "cot_sle", "cot_ult", "cot_sshr", "cot_eq", "cot_land", "cot_sge", "cot_slt", "cot_ne", "cot_uge", "cot_band", "cot_bor", "cot_ushr", "cot_xor", "cot_smod":
		kind = dbscheme.GetHexrayExprKind(nodeType)
		extractExpr(tw, expr.Get("left"), lbl, 0, true)
		extractExpr(tw, expr.Get("right"), lbl, 1, true)

	case "cot_add", "cot_lor", "cot_mul", "cot_sub":
		kind = dbscheme.GetHexrayExprKind(nodeType)
		extractExpr(tw, expr.Get("left"), lbl, 0, true)
		extractExpr(tw, expr.Get("right"), lbl, 1, true)
	case "cot_lnot", "cot_ref", "cot_bnot":
		kind = dbscheme.GetHexrayExprKind(nodeType)
		extractExpr(tw, expr.Get("expr"), lbl, 0, false)

	case "Parameter", "Identifier", "LabelIdent":
		kind = dbscheme.GetHexrayExprKind(nodeType)
		name := expr.Get("name").String()
		typ := expr.Get("type").String()
		dbscheme.LiteralsTable.Emit(tw, lbl, name, name)
		useTyp, _ := lookupTypeLabel(tw, typ)
		objlbl, exists := tw.Labeler.LookupObjectID(expr, useTyp, false)
		if objlbl == trap.InvalidLabel {
			log.Printf("Omitting use binding to unknown object %v", expr.String())
		} else {
			if !exists {
				otyp := "Var"
				if nodeType == "LabelIdent" {
					otyp = "Label"
				}
				extractObject(tw, name, otyp, objlbl)
				scopeLabel := tw.Labeler.GetCurrentScopeLabel()
				dbscheme.ObjectScopesTable.Emit(tw, objlbl, scopeLabel)
				tw.Labeler.SetLabelToTypeLabel(objlbl.String(), useTyp)
			}
			dbscheme.UsesTable.Emit(tw, lbl, objlbl)
		}

	case "MemberPtr":
		kind = dbscheme.GetHexrayExprKind(nodeType)
		extractExpr(tw, expr.Get("base"), lbl, 0, false)
		//member := expr.Get("member").String()
		typ := expr.Get("type").String()
		emitIdentExpr(tw, attributes, lbl, 1, expr.Get("code").String(), typ, false)

	case "ArrayIndexAccess":
		kind = dbscheme.GetHexrayExprKind(nodeType)
		extractExpr(tw, expr.Get("base"), lbl, 0, false)
		extractExpr(tw, expr.Get("index"), lbl, 1, false)

	case "Star":
		kind = dbscheme.GetHexrayExprKind(nodeType)
		extractExpr(tw, expr.Get("expr"), lbl, 0, false)
	case "Call":
		kind = dbscheme.GetHexrayExprKind(nodeType)
		if !emitFunctionName(tw, expr.Get("name"), lbl, 0, false) {
			return
		}
		extractExprs(tw, expr.Get("args").Array(), lbl, 1, 1)
	case "Number":
		kind = dbscheme.GetHexrayExprKind(nodeType)

		value := expr.Get("value").String()
		dbscheme.LiteralsTable.Emit(tw, lbl, value, value)
	case "Cast", "cot_preinc", "cot_predec", "cot_postdec", "cot_postinc":
		extractExpr(tw, expr.Get("expr"), parent, idx, false)
		return

	case "Empty":
		return

	case "Tern":
		return

	case "cot_asg", "cot_asgbor", "cot_asgband", "cot_asgsub", "cot_asgadd", "cot_comma":
		kind = dbscheme.GetHexrayExprKind("Call")
		if !emitHelperFunctionName(tw, expr, "ida2codeql_assign_helper", lbl, 0) {
			return
		}
		leftValue, _ := sjson.Set(expr.Get("left").String(), "type", "int *")
		rightValue, _ := sjson.Set(expr.Get("right").String(), "type", "int")

		extractExpr(tw, gjson.Parse(leftValue), lbl, 1, false)
		extractExpr(tw, gjson.Parse(rightValue), lbl, 2, false)
	default:
		log.Fatalf("unknown expr of type %v", nodeType)
	}

	dbscheme.ExprsTable.Emit(tw, lbl, kind, parent, idx)
	extractNodeLocation(tw, expr, lbl)
}

// extractExprs extracts AST information for a list of expressions, which are children of
// the given parent
// `idx` is the index of the first child in the list, and `dir` is the index increment of
// each child over its preceding child (usually either 1 for assigning increasing indices, or
// -1 for decreasing indices)
func extractExprs(tw *trap.Writer, exprs []gjson.Result, parent trap.Label, idx int, dir int) {
	for _, expr := range exprs {
		extractExpr(tw, expr, parent, idx, false)
		idx += dir
	}
}

func extractFields(tw *trap.Writer, fields []gjson.Result, parent trap.Label, idx int, dir int) {
	for _, field := range fields {
		fieldLbl := tw.Labeler.LocalIDWithPad(field, "_field", true)
		dbscheme.FieldsTable.Emit(tw, fieldLbl, parent, idx)
		extractNodeLocation(tw, field, fieldLbl)

		name := field.Get("name").String()
		typ := field.Get("type").String()
		emitIdentExpr(tw, field.Get("attributes"), fieldLbl, 1, name, typ, true) // name 是 field 的第一个成员
		emitTypeExpr(tw, field.Get("attributes"), fieldLbl, 0, typ, typ, false)  // 0 是 type
		idx += dir
	}

}

func extractReturnType(tw *trap.Writer, parent trap.Label, returnType string) {
	// 生成返回值节点
	x := fmt.Sprintf("{\"nodeType\": \"Identifier\",\"attributes\": "+
		"{  \"ea\": \"%s\",  \"treeindex\": \"%s\"},"+
		"\"name\": \"%s\",\"code\": \"%s\","+
		"\"type\": \"%s\"}", 0, 2, "PlaceHoleReturnVal", "PlaceHoleReturnVal", returnType)

	field := gjson.Parse(x)

	fieldLbl := tw.Labeler.LocalIDWithPad(field, "_returnLabl", true)
	dbscheme.FieldsTable.Emit(tw, fieldLbl, parent, -1)
	extractNodeLocation(tw, field, fieldLbl)

	//name := field.Get("name").String()
	typ := field.Get("type").String()
	//emitIdentExpr(tw, field.Get("attributes"), fieldLbl, 1, name, typ, true) // name 是 field 的第一个成员
	emitTypeExpr(tw, field.Get("attributes"), fieldLbl, 0, typ, typ, false) // 0 是 type
}

// extractTypeOf looks up the type of `expr`, extracts it if it hasn't previously been
// extracted, and associates it with `expr` in the `type_of` table
func extractTypeOf(tw *trap.Writer, expr gjson.Result, lbl trap.Label) {
	tp := expr.Get("type")
	if tp.Exists() {
		tpn := tp.String()
		if tpn == "?" || tpn == "" {
			tpn = "int"
		}
		tplbl, _ := lookupTypeLabel(tw, tpn)
		tw.Labeler.SetLabelToTypeLabel(lbl.String(), tplbl)
		dbscheme.TypeOfTable.Emit(tw, lbl, tplbl)
	}
}

// extractValueOf looks up the value of `expr`, and associates it with `expr` in
// the `consts` table
func extractValueOf(tw *trap.Writer, expr gjson.Result, lbl trap.Label) {
	value := expr.Get("value").String()
	dbscheme.ConstValuesTable.Emit(tw, lbl, value, value)
}

// extractStmt extracts AST information for a given statement and all other statements or expressions
// nested inside it
func extractStmt(tw *trap.Writer, stmt gjson.Result, parent trap.Label, idx int) {

	nodeType := stmt.Get("nodeType").String()
	lbl := tw.Labeler.LocalIDWithPad(stmt, "_stmt_"+nodeType, true)
	var kind int
	switch nodeType {

	case "Block":
		kind = dbscheme.GetHexrayStmtKind(nodeType)
		extractStmts(tw, stmt.Get("stmts").Array(), lbl, 0, 1)
		//emitScopeNodeInfo(tw, stmt, lbl)
	case "Expression":
		expr := stmt.Get("expr")
		kind = dbscheme.GetHexrayStmtKind("Expression")
		extractExpr(tw, expr, lbl, 0, true)

	case "cot_preinc", "cot_predec", "cot_postdec", "cot_postinc":
		kind = dbscheme.GetHexrayStmtKind(nodeType)
		extractExpr(tw, stmt.Get("expr"), lbl, 0, false)

	case "Return":
		kind = dbscheme.GetHexrayStmtKind(nodeType)
		extractExpr(tw, stmt.Get("expr"), lbl, 0, true)
	case "If":
		kind = dbscheme.GetHexrayStmtKind(nodeType)
		extractExpr(tw, stmt.Get("cond"), lbl, 1, false)
		extractStmt(tw, stmt.Get("then").Array()[0], lbl, 2)

		els := stmt.Get("else").Array()
		if len(els) > 0 {
			// else always one block stmt
			extractStmt(tw, els[0], lbl, 3)
		}
		//emitScopeNodeInfo(tw, stmt, lbl)

	case "While", "Do":
		kind = dbscheme.GetHexrayStmtKind(nodeType)
		extractExpr(tw, stmt.Get("cond"), lbl, 1, false)
		extractStmt(tw, stmt.Get("body"), lbl, 3)

	case "For":
		kind = dbscheme.GetHexrayStmtKind(nodeType)
		extractExpr(tw, stmt.Get("init"), lbl, 0, false)
		extractExpr(tw, stmt.Get("cond"), lbl, 1, false)
		extractExpr(tw, stmt.Get("step"), lbl, 2, false)
		extractStmt(tw, stmt.Get("body"), lbl, 3)

	case "Break":
		return
	case "Switch":
		kind = dbscheme.GetHexrayStmtKind(nodeType)
		extractExpr(tw, stmt.Get("cond"), lbl, 1, false)

		cases := stmt.Get("cases").Array()

		{
			blockKind := dbscheme.GetHexrayStmtKind("Block")
			blockLbl := tw.Labeler.LocalIDWithPad(stmt, "_stmt_inner_block_"+nodeType, true)

			for i := 0; i < len(cases); i++ {
				cas := cases[i].Array()

				casKind := dbscheme.GetHexrayStmtKind("CaseClauseType")
				casLbl := tw.Labeler.LocalIDWithPad(stmt, "_stmt_inner_block_case_"+nodeType, true)

				//values := cas[0]

				caseBody := cas[1]

				extractStmt(tw, caseBody, casLbl, 0)

				dbscheme.StmtsTable.Emit(tw, casLbl, casKind, blockLbl, 2)
				extractNodeLocation(tw, stmt, casLbl)
			}

			dbscheme.StmtsTable.Emit(tw, blockLbl, blockKind, lbl, 2)
			extractNodeLocation(tw, stmt, blockLbl)
		}

	case "LocalDecl":
		kind = dbscheme.GetHexrayStmtKind(nodeType)
		emitLocalDecl(tw, stmt, lbl, 0)
	case "Label":
		kind = dbscheme.GetHexrayStmtKind(nodeType)
		extractExpr(tw, stmt.Get("expr"), lbl, 0, false)
		extractStmt(tw, stmt.Get("stmts"), lbl, 1)
	case "Goto":
		kind = dbscheme.GetHexrayStmtKind(nodeType)
		extractExpr(tw, stmt.Get("label"), lbl, 0, false)

	default:
		log.Fatalf("unknown statement of type %v", nodeType)
	}
	dbscheme.StmtsTable.Emit(tw, lbl, kind, parent, idx)
	extractNodeLocation(tw, stmt, lbl)
}

// extractStmts extracts AST information for a list of statements, which are children of
// the given parent
// `idx` is the index of the first child in the list, and `dir` is the index increment of
// each child over its preceding child (usually either 1 for assigning increasing indices, or
// -1 for decreasing indices)
func extractStmts(tw *trap.Writer, stmts []gjson.Result, parent trap.Label, idx int, dir int) {
	for _, stmt := range stmts {
		extractStmt(tw, stmt, parent, idx)
		idx += dir
	}
}

// extractElementType extracts `element` as the element type of the container type `container`
func extractElementType(tw *trap.Writer, container trap.Label, typeMap map[string]gjson.Result, element gjson.Result) {
	dbscheme.ElementTypeTable.Emit(tw, container, extractType(tw, typeMap, element))
}

// extractComponentType extracts `component` as the `idx`th component type of `parent` with name `name`
func extractComponentType(tw *trap.Writer, parent trap.Label, idx int, name string, typeMap map[string]gjson.Result, component gjson.Result) trap.Label {
	lbl := extractType(tw, typeMap, component)
	dbscheme.ComponentTypesTable.Emit(tw, parent, idx, name, lbl)
	return lbl
}

// extractComponentType extracts `component` as the `idx`th component type of `parent` with name `name`
func extractComponentTypeString(tw *trap.Writer, parent trap.Label, idx int, name string, component string) {
	lbl, _ := lookupTypeLabel(tw, component)
	dbscheme.ComponentTypesTable.Emit(tw, parent, idx, name, lbl)
}

// extractBaseType extracts `base` as the base type of the pointer type `ptr`
func extractBaseType(tw *trap.Writer, ptr trap.Label, typeMap map[string]gjson.Result, base gjson.Result) {
	dbscheme.BaseTypeTable.Emit(tw, ptr, extractType(tw, typeMap, base))
}

// extractType extracts type information for `tp` and returns its associated label;
// types are only extracted once, so the second time `extractType` is invoked it simply returns the label
func extractType(tw *trap.Writer, typeMap map[string]gjson.Result, tp gjson.Result) trap.Label {
	lbl, exists := getTypeLabel(tw, typeMap, tp)
	if !exists {
		var kind int
		typs := tp.Get("type").String()
		switch typs {
		case "Void", "Unknown", "Float", "Int":
			kind = dbscheme.GetTypeKind("inttype")
		case "Array":
			kind = dbscheme.GetTypeKind("arraytype")
			dbscheme.ArrayLengthTable.Emit(tw, lbl, fmt.Sprintf("%d", tp.Get("elem_count").Num))
			extractElementType(tw, lbl, typeMap, tp.Get("elem_type"))
		case "Struct":
			kind = dbscheme.GetTypeKind("structtype")
			members := tp.Get("members").Array()
			for i := 0; i < len(members); i++ {
				field := members[i]

				// ensure the field is associated with a label - note that
				// struct fields do not have a parent scope, so they are not
				// dealt with by `extractScopes`
				fieldlbl, exists := tw.Labeler.FieldID(field, i, lbl, false)
				if !exists {
					extractObject(tw, field.Get("name").String(), "Var", fieldlbl)
				}
				dbscheme.FieldStructsTable.Emit(tw, fieldlbl, lbl)
				name := field.Get("name").String()
				typLbl := extractComponentType(tw, lbl, i, name, typeMap, field.Get("type"))

				tw.Labeler.SetLabelToTypeLabel(fieldlbl.String(), typLbl)

			}
		case "Pointer":
			kind = dbscheme.GetTypeKind("pointertype")
			pointed := tp.Get("pointed_type").String()
			extractBaseType(tw, lbl, typeMap, typeMap[pointed])
		case "function_signature":
			kind = dbscheme.GetTypeKind("signaturetype")
			param_types := tp.Get("param_types").Array()
			for i := 0; i < len(param_types); i++ {
				param_type := param_types[i].String()
				extractComponentTypeString(tw, lbl, i+1, "", param_type)
			}
			extractComponentTypeString(tw, lbl, -1, "", tp.Get("ret_type").String())
		}
		if tw.Labeler.SetEmitStatus(lbl.String(), lbl) {
			dbscheme.TypesTable.Emit(tw, lbl, kind)
		}
	}

	if tp.Get("type").String() == "function_signature" {
		funcName := tp.Get("function_name").String()
		tw.Labeler.AddFunctionSignature(funcName, lbl)
	}
	return lbl
}

// getTypeLabel looks up the label associated with `tp`, creating a new label if
// it does not have one yet; the second result indicates whether the label
// already existed
//
// Type labels refer to global keys to ensure that if the same type is
// encountered during the extraction of different files it is still ultimately
// mapped to the same entity. In particular, this means that keys for compound
// types refer to the labels of their component types. For named types, the key
// is constructed from their globally unique ID. This prevents cyclic type keys
// since type recursion in Go always goes through named types.
func getTypeLabel(tw *trap.Writer, typeMap map[string]gjson.Result, tp gjson.Result) (trap.Label, bool) {
	typeName := tp.Get("name").String()
	typs := tp.Get("type").String()
	lbl, exists := tw.Labeler.TypeLabels[typeName]
	if !exists {
		//todo: import type before
		switch typs {
		case "Int":
			lbl = tw.Labeler.GlobalID(fmt.Sprintf("%d;basictype", 2)) // | 2 = @inttype
		case "Pointer":
			pointed := tp.Get("pointed_type").String()
			//base := extractType(tw, typeMap, typeMap[pointed])
			lbl = tw.Labeler.GlobalID(fmt.Sprintf("{%s};pointertype", pointed))
		case "Float":
			lbl = tw.Labeler.GlobalID(fmt.Sprintf("%d;basictype", 14)) // | 14 = @float64type
		case "Void":
			lbl = tw.Labeler.GlobalID(fmt.Sprintf("%d;Void", 2))
		case "Unknown":
			lbl = tw.Labeler.GlobalID(fmt.Sprintf("%d;Unknown", 2))
		case "Array":
			len := tp.Get("elem_count").Num
			elem := extractType(tw, typeMap, tp.Get("elem_type"))
			lbl = tw.Labeler.GlobalID(fmt.Sprintf("%d,{%s};arraytype", len, elem))
		case "Struct", "Union":
			var b strings.Builder
			members := tp.Get("members").Array()
			for i := 0; i < len(members); i++ {
				field := members[i]
				fieldTypeLbl := extractType(tw, typeMap, field.Get("type"))
				if i > 0 {
					b.WriteString(",")
				}
				name := field.Get("name")
				fmt.Fprintf(&b, "%s,{%s}", name, fieldTypeLbl)
			}
			lbl = tw.Labeler.GlobalID(fmt.Sprintf("%s;structtype", b.String()))
		case "function_signature":
			lbl = tw.Labeler.GlobalID(typeName)
		default:
			log.Fatalf("unexpected type %v", tp)
		}
		tw.Labeler.TypeLabels[typeName] = lbl

	}
	return lbl, exists
}

func lookupTypeLabel(tw *trap.Writer, tp string) (trap.Label, bool) {
	lbl, exists := tw.Labeler.TypeLabels[tp]
	if !exists {
		lbl, _ = lookupTypeLabel(tw, "int")
		tw.Labeler.TypeLabels[tp] = lbl
	}
	return lbl, exists
}

// extractNumLines extracts lines-of-code and lines-of-comments information for the
// given file
func extractNumLines(tw *trap.Writer, fileName string, ast *ast.File) {
	f := tw.Package.Fset.File(ast.Pos())

	lineCount := f.LineCount()

	// count lines of code by tokenizing
	linesOfCode := 0
	src, err := os.ReadFile(fileName)
	if err != nil {
		log.Fatalf("Unable to read file %s.", fileName)
	}
	var s scanner.Scanner
	lastCodeLine := -1
	s.Init(f, src, nil, 0)
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		} else if tok != token.ILLEGAL && !(tok == token.SEMICOLON && lit == "\n") {
			// specifically exclude newlines that are treated as semicolons
			tkStartLine := f.Position(pos).Line
			tkEndLine := tkStartLine + strings.Count(lit, "\n")
			if tkEndLine > lastCodeLine {
				if tkStartLine <= lastCodeLine {
					// if the start line is the same as the last code line we've seen we don't want to double
					// count it
					// note tkStartLine < lastCodeLine should not be possible
					linesOfCode += tkEndLine - lastCodeLine
				} else {
					linesOfCode += tkEndLine - tkStartLine + 1
				}
				lastCodeLine = tkEndLine
			}
		}
	}

	// count lines of comments by iterating over ast.Comments
	linesOfComments := 0
	for _, cg := range ast.Comments {
		for _, g := range cg.List {
			fset := tw.Package.Fset
			startPos, endPos := fset.Position(g.Pos()), fset.Position(g.End())
			linesOfComments += endPos.Line - startPos.Line + 1
		}
	}

	dbscheme.NumlinesTable.Emit(tw, tw.Labeler.FileLabel(), lineCount, linesOfCode, linesOfComments)
}

// For a type `t` which is the type of a field of an interface type, return
// whether `t` a type set literal which is not a union type. Note that a field
// of an interface must be a method signature, an embedded interface type or a
// type set literal.
func isNonUnionTypeSetLiteral(t types.Type) bool {
	if t == nil {
		return false
	}
	switch t.Underlying().(type) {
	case *types.Interface, *types.Union, *types.Signature:
		return false
	default:
		return true
	}
}

// Given a type `t`, return a union with a single term that is `t` without a
// tilde.
func createUnionFromType(t types.Type) *types.Union {
	return types.NewUnion([]*types.Term{types.NewTerm(false, t)})
}

// Go through a `FieldList` and update the types of all type set literals which
// are not already union types to be union types. We do this by changing the
// types stored in `tw.Package.TypesInfo.Types`. Type set literals can only
// occur in two places: a type parameter declaration or a type in an interface.
func makeTypeSetLiteralsUnionTyped(tw *trap.Writer, fields *ast.FieldList) {
	if fields == nil || fields.List == nil {
		return
	}
	for i := 0; i < len(fields.List); i++ {
		x := fields.List[i].Type
		if _, alreadyOverridden := tw.TypesOverride[x]; !alreadyOverridden {
			xtp := typeOf(tw, x)
			if isNonUnionTypeSetLiteral(xtp) {
				tw.TypesOverride[x] = createUnionFromType(xtp)
			}
		}
	}
}

func typeOf(tw *trap.Writer, e ast.Expr) types.Type {
	if val, ok := tw.TypesOverride[e]; ok {
		return val
	}
	return tw.Package.TypesInfo.TypeOf(e)
}

func extractTypeParamDecls(tw *trap.Writer, params gjson.Result, parent trap.Label) {
	idx := 0
	for _, param := range params.Array() {
		lbl := tw.Labeler.LocalID(param, false)
		dbscheme.TypeParamDeclsTable.Emit(tw, lbl, parent, idx)
		extractNodeLocation(tw, param, lbl)
		extractExpr(tw, param, parent, idx, true)
		idx += 1
	}
}

// getobjectBeingUsed looks up `ident` in `tw.Package.TypesInfo.Uses` and makes
// some changes to the object to avoid returning objects relating to instantiated
// types.
func getObjectBeingUsed(tw *trap.Writer, ident *ast.Ident) types.Object {
	switch obj := tw.Package.TypesInfo.Uses[ident].(type) {
	case *types.Var:
		return obj.Origin()
	case *types.Func:
		return obj.Origin()
	default:
		return obj
	}
}

// trackInstantiatedStructFields tries to give the fields of an instantiated
// struct type underlying `tp` the same labels as the corresponding fields of
// the generic struct type. This is so that when we come across the
// instantiated field in `tw.Package.TypesInfo.Uses` we will get the label for
// the generic field instead.
func trackInstantiatedStructFields(tw *trap.Writer, tp, origintp *types.Named) {
	if tp == origintp {
		return
	}

	if instantiatedStruct, ok := tp.Underlying().(*types.Struct); ok {
		genericStruct, ok2 := origintp.Underlying().(*types.Struct)
		if !ok2 {
			log.Fatalf(
				"Error: underlying type of instantiated type is a struct but underlying type of generic type is %s",
				origintp.Underlying())
		}

		if instantiatedStruct.NumFields() != genericStruct.NumFields() {
			log.Fatalf(
				"Error: instantiated struct %s has different number of fields than the generic version %s (%d != %d)",
				instantiatedStruct, genericStruct, instantiatedStruct.NumFields(), genericStruct.NumFields())
		}

		for i := 0; i < instantiatedStruct.NumFields(); i++ {
			tw.ObjectsOverride[instantiatedStruct.Field(i)] = genericStruct.Field(i)
		}
	}
}

// skipExtractingValueForLeftOperand returns true if the left operand of `be`
// should not have its value extracted because it is an intermediate value in a
// string concatenation - specifically that the right operand is a string
// literal
func skipExtractingValueForLeftOperand(tw *trap.Writer, be *ast.BinaryExpr) bool {
	// check `be` has string type
	tpVal := tw.Package.TypesInfo.Types[be]
	if tpVal.Value == nil || tpVal.Value.Kind() != constant.String {
		return false
	}
	// check that the right operand of `be` is a basic literal
	if _, isBasicLit := be.Y.(*ast.BasicLit); !isBasicLit {
		return false
	}
	// check that the left operand of `be` is not a basic literal
	if _, isBasicLit := be.X.(*ast.BasicLit); isBasicLit {
		return false
	}
	return true
}
