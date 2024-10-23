package trap

import (
	"fmt"
	"github.com/github/codeql-go/extractor/util"
	"github.com/tidwall/gjson"
	"go/types"
)

// Label represents a label
type Label struct {
	id string
}

// InvalidLabel represents an uninitialized or otherwise invalid label
var InvalidLabel Label

func (lbl *Label) String() string {
	return lbl.id
}

// Labeler is used to represent labels for a file. It is used to write
// associate objects with labels.
type Labeler struct {
	tw            *Writer
	current_scope string
	prev_scope    string
	nextid        int
	fileLabel     Label
	nodeLabels    map[string]Label // labels associated with AST nodes
	scopeLabels   map[string]Label // labels associated with scopes
	objectLabels  map[string]Label // labels associated with objects (that is, declared entities)
	TypeLabels    map[string]Label // labels associated with types
	keyLabels     map[string]Label
	emitTypes     map[string]Label
	objectTypes   map[string]Label
	funcSigLabels map[string]Label
}

func newLabeler(tw *Writer) *Labeler {
	return &Labeler{
		tw,
		"universe",
		"universe",
		10000,
		InvalidLabel,
		make(map[string]Label),
		make(map[string]Label),
		make(map[string]Label),
		make(map[string]Label),
		make(map[string]Label),
		make(map[string]Label),
		make(map[string]Label),
		make(map[string]Label),
	}
}

func (l *Labeler) nextID() string {
	var id = l.nextid
	l.nextid++
	return fmt.Sprintf("#%d", id)
}

// GlobalID associates a label with the given `key` and returns it
func (l *Labeler) GlobalID(key string) Label {
	label, exists := l.keyLabels[key]
	if !exists {
		id := l.nextID()
		fmt.Fprintf(l.tw.wzip, "%s=@\"%s\"\n", id, escapeString(key))
		label = Label{id}
		l.keyLabels[key] = label
	}
	return label
}

// GlobalID associates a label with the given `key` and returns it
func (l *Labeler) SetEmitStatus(key string, lbl Label) bool {
	_, exists := l.emitTypes[key]
	if !exists {
		l.emitTypes[key] = lbl
		return true
	}
	return false
}

func (l *Labeler) AddFunctionSignature(signame string, lbl Label) bool {
	_, exists := l.funcSigLabels[signame]
	if !exists {
		l.funcSigLabels[signame] = lbl
		return true
	}
	return false
}

func (l *Labeler) LookupFunctionSignature(signame string) Label {
	lbl, _ := l.funcSigLabels[signame]
	return lbl
}

// FileLabel returns the label for a file with path `path`.
func (l *Labeler) FileLabel() Label {
	if l.fileLabel == InvalidLabel {
		l.fileLabel = l.FileLabelFor(l.tw.path)
	}
	return l.fileLabel
}

// FileLabelFor returns the label for the file for which the trap writer `tw` is associated
func (l *Labeler) FileLabelFor(path string) Label {
	return l.GlobalID(util.EscapeTrapSpecialChars(path) + ";sourcefile")
}

func (l *Labeler) LabelToTypeLabel(key string) Label {
	lbl, _ := l.objectTypes[key]
	return lbl
}

func (l *Labeler) SetLabelToTypeLabel(key string, lbl Label) {
	l.objectTypes[key] = lbl
}

func getKeyForObject(nd gjson.Result, scope string, useEaLbl bool) string {
	var key string
	attr := nd.Get("attributes")
	if nd.Get("name").Exists() {
		name := nd.Get("name").Str

		if scope == "" {
			key = name
		} else {
			key = scope + "::" + name
		}
		if useEaLbl {
			key = key + ":" + attr.Get("ea").String()
		}
	} else if nd.Get("attributes").Exists() {
		key = attr.Get("ea").String() + "::" + attr.Get("treeindex").String() + "--" + nd.Get("code").String()
	} else {
		key = nd.Get("ea").String() + "::" + nd.Get("treeindex").String()
	}
	return key
}

func getKeyForObjectLookup(nd gjson.Result, scope string) string {
	var key string
	attr := nd.Get("attributes")
	if nd.Get("name").Exists() {
		name := nd.Get("name").Str
		key = scope + "::" + name
	} else if nd.Get("attributes").Exists() {
		key = attr.Get("ea").String() + "::" + attr.Get("treeindex").String() + "--" + nd.Get("code").String()
	} else {
		key = nd.Get("ea").String() + "::" + nd.Get("treeindex").String()
	}
	return key
}

// LocalID associates a label with the given AST node `nd` and returns it
func (l *Labeler) LocalID(nd gjson.Result, useEalbl bool) Label {
	key := getKeyForObject(nd, l.current_scope, useEalbl)
	label, exists := l.nodeLabels[key]
	if !exists {
		label = l.FreshID()
		l.nodeLabels[key] = label
	}
	return label
}

// LocalID associates a label with the given AST node `nd` and returns it
func (l *Labeler) GetCurrentScopeLabel() Label {
	label := l.ScopeID(l.current_scope, "")
	return label
}

func (l *Labeler) LocalIDWithPad(nd gjson.Result, pads string, useEalbl bool) Label {
	key := getKeyForObject(nd, l.current_scope, useEalbl) + pads
	label, exists := l.nodeLabels[key]
	if !exists {
		label = l.FreshID()
		l.nodeLabels[key] = label
	}
	return label
}

// FreshID creates a fresh label and returns it
func (l *Labeler) FreshID() Label {
	id := l.nextID()
	fmt.Fprintf(l.tw.wzip, "%s=*\n", id)
	return Label{id}
}

// ScopeID associates a label with the given scope and returns it
func (l *Labeler) ScopeID(scope string, pkg string) Label {
	label, exists := l.scopeLabels[scope]
	if !exists {
		if scope == "universe" {
			label = l.GlobalID("universe;scope")
		} else {
			if pkg == scope {
				// if this scope is the package scope
				pkgLabel := l.GlobalID(util.EscapeTrapSpecialChars(pkg) + ";package")
				label = l.GlobalID("{" + pkgLabel.String() + "};scope")
			} else {
				label = l.FreshID()
			}
		}
		l.scopeLabels[scope] = label
	}
	return label
}

func (l *Labeler) SetScope(scope string) string {
	l.prev_scope = l.current_scope
	l.current_scope = scope
	return l.prev_scope
}

func (l *Labeler) ResetScope() string {
	l.current_scope = l.prev_scope
	return l.current_scope
}

func (l *Labeler) GetCurrentScope() string {
	return l.current_scope
}

// LookupObjectID looks up the label associated with the given object and returns it; if the object does not have
// a label yet, it tries to construct one based on its scope and/or name, and otherwise returns InvalidLabel
func (l *Labeler) LookupObjectID(object gjson.Result, typelbl Label, useEaLbl bool) (Label, bool) {
	key := getKeyForObject(object, l.current_scope, useEaLbl)
	label, exists := l.objectLabels[key]
	if !exists {
		label, exists = l.ScopedObjectID(object, useEaLbl)
	}
	return label, exists
}

func (l *Labeler) LookupObjectIDWithoutScope(object gjson.Result, typelbl Label, useEaLbl bool) (Label, bool) {
	key := getKeyForObject(object, "", useEaLbl)
	label, exists := l.objectLabels[key]
	if !exists {
		label, exists = l.ScopedObjectIDWithoutScope(object, useEaLbl)
	}
	return label, exists
}

// ScopedObjectID associates a label with the given object and returns it,
// together with a flag indicating whether the object already had a label
// associated with it; the object must have a scope, since the scope's label is
// used to construct the label of the object.
//
// There is a special case for variables that are method receivers. When this is
// detected, we must construct a special label, as the variable can be reached
// from several files via the method. As the type label is required to construct
// the receiver object id, it is also required here.
func (l *Labeler) ScopedObjectID(object gjson.Result, useEalbl bool) (Label, bool) {
	key := getKeyForObject(object, l.current_scope, useEalbl)
	label, exists := l.objectLabels[key]
	if !exists {
		scopeLbl := l.ScopeID(l.current_scope, "")
		label = l.GlobalID(fmt.Sprintf("{%v},%s;object", scopeLbl, key))
		l.objectLabels[key] = label
	}
	return label, exists
}

func (l *Labeler) ScopedObjectIDWithoutScope(object gjson.Result, useEalbl bool) (Label, bool) {
	key := getKeyForObject(object, "", useEalbl)
	label, exists := l.objectLabels[key]
	if !exists {
		label = l.GlobalID(fmt.Sprintf("%s;object", key))
		l.objectLabels[key] = label
	}
	return label, exists
}

// findMethodWithGivenReceiver finds a method with `object` as its receiver, if one exists
func findMethodWithGivenReceiver(object types.Object) *types.Func {
	meth := findMethodOnTypeWithGivenReceiver(object.Type(), object)
	if meth != nil {
		return meth
	}
	if pointerType, ok := object.Type().(*types.Pointer); ok {
		meth = findMethodOnTypeWithGivenReceiver(pointerType.Elem(), object)
	}
	return meth
}

// findMethodWithGivenReceiver finds a method on type `tp` with `object` as its receiver, if one exists
func findMethodOnTypeWithGivenReceiver(tp types.Type, object types.Object) *types.Func {
	if namedType, ok := tp.(*types.Named); ok {
		for i := 0; i < namedType.NumMethods(); i++ {
			meth := namedType.Method(i)
			if object == meth.Type().(*types.Signature).Recv() {
				return meth
			}
		}
	}
	return nil
}

// ReceiverObjectID associates a label with the given object and returns it, together with a flag indicating whether
// the object already had a label associated with it; the object must be the receiver of `methlbl`, since that label
// is used to construct the label of the object
func (l *Labeler) ReceiverObjectID(object gjson.Result, methlbl Label, useEalbl bool) (Label, bool) {
	key := getKeyForObject(object, l.current_scope, useEalbl)
	label, exists := l.objectLabels[key]
	if !exists {
		// if we can't, construct a special label
		label = l.GlobalID(fmt.Sprintf("{%v},%s;receiver", methlbl, object.Get("name").String()))
		l.objectLabels[key] = label
	}
	return label, exists
}

// FieldID associates a label with the given field and returns it, together with
// a flag indicating whether the field already had a label associated with it;
// the field must belong to `structlbl`, since that label is used to construct
// the label of the field. When the field name is the blank identifier `_`,
// `idx` is used to generate a unique name.
func (l *Labeler) FieldID(field gjson.Result, idx int, structlbl Label, useEalbl bool) (Label, bool) {
	key := getKeyForObject(field, l.current_scope, useEalbl)
	label, exists := l.objectLabels[key]
	if !exists {
		name := field.Get("name").String()
		// there can be multiple fields with the blank identifier, so use index to
		// distinguish them
		if name == "_" {
			name = fmt.Sprintf("_%d", idx)
		}

		label = l.GlobalID(fmt.Sprintf("{%v},%s;field", structlbl, name))
		l.objectLabels[key] = label
	}
	return label, exists
}

// MethodID associates a label with the given method and returns it, together with a flag indicating whether
// the method already had a label associated with it; the method must belong to `recvtyplbl`, since that label
// is used to construct the label of the method
func (l *Labeler) MethodID(method gjson.Result, recvtyplbl Label, useEalbl bool) (Label, bool) {
	key := getKeyForObject(method, l.current_scope, useEalbl)
	label, exists := l.objectLabels[key]
	if !exists {
		label = l.GlobalID(fmt.Sprintf("{%v},%s;method", recvtyplbl, method.Get("name").String()))
		l.objectLabels[key] = label
	}
	return label, exists
}
