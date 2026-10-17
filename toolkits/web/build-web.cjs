'use strict';
// Fixed browser compilation. No package scripts, plugins, network or source execution.
const fs=require('node:fs'),path=require('node:path');
const source=path.resolve(process.argv[2]),out=path.resolve(process.argv[3]);
if(!path.isAbsolute(source)||!path.isAbsolute(out)||source===out)throw Error('paths_required');
const toolkit=__dirname;
process.env.ESBUILD_BINARY_PATH=path.join(toolkit,'node_modules/@esbuild/linux-x64/bin/esbuild');
if(process.platform==='win32')process.env.ESBUILD_BINARY_PATH=path.join(toolkit,'node_modules/@esbuild/win32-x64/esbuild.exe');
const esbuild=require(path.join(toolkit,'node_modules/esbuild/lib/main.js'));
const entry=['src/main.js','src/main.ts','src/main.jsx','src/main.tsx'].filter(n=>fs.existsSync(path.join(source,n)));
if(entry.length!==1)throw Error('exactly_one_js_entry_required');
fs.mkdirSync(out,{recursive:true});
const result=esbuild.buildSync({absWorkingDir:source,entryPoints:[path.join(source,entry[0])],outfile:path.join(out,'app.js'),bundle:true,format:'iife',platform:'browser',target:['es2020'],minify:true,sourcemap:false,legalComments:'inline',nodePaths:[path.join(toolkit,'node_modules')],loader:{'.png':'dataurl','.jpg':'dataurl','.jpeg':'dataurl','.webp':'dataurl','.svg':'dataurl','.woff2':'dataurl'},logLevel:'warning',metafile:true});
for(const [name,meta] of Object.entries(result.metafile.inputs)){
 const resolved=path.resolve(source,name),within=(base)=>resolved.startsWith(base+path.sep);
 if(!within(source)&&!within(path.join(toolkit,'node_modules')))throw Error('import_scope_denied');
 if((meta.imports||[]).some(i=>i.external))throw Error('external_import_denied');
}
let html=fs.readFileSync(path.join(source,'index.html'),'utf8');
html=html.replace(/<script\b[^>]*\bsrc=["'][^"']*["'][^>]*>\s*<\/script\s*>/gi,'');
html=html.replace(/<link\b[^>]*\brel=["']stylesheet["'][^>]*>/gi,'');
if(!/<html\b/i.test(html)||!/<body\b/i.test(html))throw Error('html_required');
if(fs.existsSync(path.join(out,'app.css'))){fs.renameSync(path.join(out,'app.css'),path.join(out,'styles.css'));html=html.replace(/<\/head\s*>/i,'<link rel="stylesheet" href="./styles.css"></head>');}
else if(fs.existsSync(path.join(source,'src/styles.css'))){fs.copyFileSync(path.join(source,'src/styles.css'),path.join(out,'styles.css'));html=html.replace(/<\/head\s*>/i,'<link rel="stylesheet" href="./styles.css"></head>');}
html=html.replace(/<\/body\s*>/i,'<script defer src="./app.js"></script></body>');
fs.writeFileSync(path.join(out,'index.html'),html,'utf8');
const assets=path.join(source,'assets');
if(fs.existsSync(assets))fs.cpSync(assets,path.join(out,'assets'),{recursive:true,dereference:false,errorOnExist:true});
console.log(JSON.stringify({schema:'awema-fixed-build-v1',entrypoint:'dist/index.html',esbuild:esbuild.version}));
