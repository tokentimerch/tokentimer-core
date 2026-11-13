//go:build windows && credentialpipeexperiment && registrycredentialexperiment

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// Only run on a disposable SYSTEM lab whose HKLM fixture was pre-provisioned.
// It exercises Node -> authenticated Go pipe -> protected HKLM -> real TLS.
// It does not install a service, rotate a credential, send ACK, or prove
// provenance of an existing installation.
func TestBoundRotationRealInteropLab(t *testing.T) {
	if os.Getenv("TT_BOUND_LAB") != "1" {
		t.Skip("requires isolated SYSTEM lab and pre-provisioned fixture")
	}
	if os.Getenv("TT_TEST_TLS_DIR") == "" || os.Getenv("TT_BOUND_ORIGIN") == "" {
		t.Fatal("missing lab fixture")
	}
	node, err := exec.LookPath("node.exe")
	if err != nil {
		t.Fatal(err)
	}
	module, err := filepath.Abs(filepath.Join("..", "src", "protocol", "bound-rotation-startup.js"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := newCredentialPipeSession(pipeTestSDDL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	packet, err := p.bootstrap()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(packet)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	script := `const fs=require('node:fs'),path=require('node:path'),https=require('node:https'),c=require(process.argv[1]),p=require(process.argv[2]);const d=process.env.TT_TEST_TLS_DIR,o=process.env.TT_BOUND_ORIGIN,i={id:'11111111-1111-4111-8111-111111111111',agentId:'agent-a',workspaceId:'22222222-2222-4222-8222-222222222222'},read=n=>fs.readFileSync(path.join(d,n),'utf8'),token='ttagent_'+'1'.repeat(16)+'_'+'2'.repeat(64);const server=https.createServer({key:read('leaf.key'),cert:read('leaf.pem')},(q,r)=>{if(q.headers.authorization!=='Bearer '+token){r.writeHead(401).end();return}q.resume();q.on('end',()=>{r.setHeader('content-type','application/json');r.end(JSON.stringify(i))})});(async()=>{await new Promise((r,j)=>server.listen(Number(new URL(o).port),'127.0.0.1',r).once('error',j));const s=await p.receiveCredentialPipeBootstrap(process.stdin);try{const v=await c.recoverBoundRotationCredential({session:s,enrolledIdentity:i,origin:o,caBundlePem:read('ca.pem')});if(v!==token)throw Error('credential');process.stdout.write('ok')}finally{s.dispose();server.close()}})().catch(()=>{server.close();process.exitCode=1});`
	pipeModule, err := filepath.Abs(filepath.Join("..", "src", "protocol", "credential-pipe.js"))
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(node, "-e", script, module, pipeModule)
	child.Stdin = reader
	var out bytes.Buffer
	child.Stdout = &out
	if err := child.Start(); err != nil {
		reader.Close()
		writer.Close()
		t.Fatal(err)
	}
	_ = reader.Close()
	defer child.Wait()
	if _, err := writer.Write(packet); err != nil {
		writer.Close()
		t.Fatal(err)
	}
	_ = writer.Close()
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(child.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	conn, err := p.pipe.accept(h, 5000)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := proveCredentialPipeServer(conn, p.key[:], time.Now().Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := serveCredentialFrame(conn, time.Now().Add(5*time.Second), handleCredentialJournalFrame); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	if out.String() != "ok" {
		t.Fatal("bound startup failed")
	}
}
