import{a as e}from"./rolldown-runtime-BYbx6iT9.js";import{$t as t,A as n,Dt as r,F as i,Mt as a,Ot as o,Pt as s,Rt as c,Sn as l,Tt as u,Vt as ee,Zt as d,an as f,en as p,gt as te,i as m,jt as ne,nn as re,ot as h,s as g,tn as ie,w as _}from"./antd-DszUL4oH.js";import{S as v}from"./vendor-3EBtILQJ.js";import{t as y}from"./gsap-CmKDPSr3.js";import{c as b,s as x}from"./api-C3vEKgG7.js";import{n as ae}from"./index-Cj-6lQap.js";import{_ as oe,r as se,v as ce}from"./recharts-AT5bvqVg.js";var S=e(l(),1),C=v(),w=`#6C5CE7`,T=`#EC4899`,le=`#F97316`,E=`#22C55E`,ue=`#06B6D4`,D=`#E8E9ED`,O=`#E8E9ED`,k=`#7C7F9A`,A=`#7C7F9A`,j=`rgba(255,255,255,0.06)`,M=`rgba(255,255,255,0.06)`,de=`#0B0D17`,N=`#141625`,P=`var(--font-display)`,F=`var(--font-body)`,I={fontFamily:`var(--font-number)`,fontVariantNumeric:`tabular-nums`},L=[`#818CF8`,`#F472B6`,`#FBBF24`,`#34D399`,`#22D3EE`,`#A78BFA`,`#FB923C`,`#F87171`,`#2DD4BF`,`#60A5FA`,`#C084FC`,`#FCA5A5`,`#7C7F9A`,`#6EE7B7`,`#FDA4AF`,`#7C7F9A`],fe=e=>{let{x:t,y:n,width:r,height:i,name:a,value:o,index:s}=e;return!r||!i||r<20||i<16?null:(0,C.jsxs)(`g`,{children:[(0,C.jsx)(`rect`,{x:t,y:n,width:r,height:i,fill:L[s%L.length],fillOpacity:.75,stroke:N,strokeWidth:2,rx:4}),r>45&&i>32&&(0,C.jsxs)(C.Fragment,{children:[(0,C.jsx)(`text`,{x:t+6,y:n+16,fill:N,fontSize:11,fontWeight:`600`,fontFamily:F,children:a}),(0,C.jsx)(`text`,{x:t+6,y:n+28,fill:`rgba(255,255,255,0.8)`,fontSize:10,style:I,children:o})]})]})},R=[{value:`ip`,label:`IP地址`,icon:(0,C.jsx)(i,{}),color:`#6C5CE7`},{value:`account`,label:`账号`,icon:(0,C.jsx)(m,{}),color:`#EC4899`},{value:`blacktalk`,label:`黑话`,icon:(0,C.jsx)(_,{}),color:`#F97316`},{value:`service`,label:`服务`,color:`#22C55E`},{value:`crypto_wallet`,label:`钱包`,color:`#06B6D4`},{value:`tool`,label:`工具`,icon:(0,C.jsx)(g,{}),color:`#8B5CF6`},{value:`person`,label:`人员`,color:`#14B8A6`},{value:`domain`,label:`域名`,icon:(0,C.jsx)(i,{}),color:`#3B82F6`},{value:`malware`,label:`恶意软件`,color:`#EF4444`},{value:`organization`,label:`组织`,color:`#8B5CF6`},{value:`email`,label:`邮箱`,color:`#F97316`},{value:`url`,label:`链接`,icon:(0,C.jsx)(i,{}),color:`#0EA5E9`},{value:`hash`,label:`哈希`,color:`#7C7F9A`},{value:`phone`,label:`电话`,color:`#22C55E`},{value:`payment_method`,label:`支付`,color:`#E11D48`},{value:`other`,label:`其他`,color:`#7C7F9A`}],z=()=>{let e=ae(),i=(0,S.useRef)(!0),[l,m]=(0,S.useState)([]),[g,_]=(0,S.useState)(!0),[v,z]=(0,S.useState)(``),[B,V]=(0,S.useState)(void 0),[H,pe]=(0,S.useState)({}),[me,U]=(0,S.useState)(!1),[W,he]=(0,S.useState)(1),[ge,_e]=(0,S.useState)(null),[ve,G]=(0,S.useState)(!1),[K,ye]=(0,S.useState)(null),[q]=c.useForm(),[J]=c.useForm(),Y=(0,S.useRef)(null),X=(0,S.useRef)(null),Z=async()=>{_(!0);try{let[e,t]=await Promise.allSettled([b.listEntities({entity_type:B,search:v||void 0}),b.getStats()]);if(!i.current){_(!1);return}if(e.status===`fulfilled`){let t=e.value;m(t?.items||[])}else m([]);t.status===`fulfilled`&&pe(t.value)}catch{i.current&&m([])}finally{i.current&&_(!1)}};(0,S.useEffect)(()=>(Z(),()=>{i.current=!1}),[v,B]),(0,S.useEffect)(()=>{if(Y.current){let e=y.fromTo(Y.current,{y:12,opacity:0},{y:0,opacity:1,duration:.4,ease:`power2.out`});return()=>{e.kill()}}},[]),(0,S.useEffect)(()=>{if(X.current){let e=X.current.querySelectorAll(`.entity-card`),t=y.fromTo(e,{y:6,opacity:0},{y:0,opacity:1,duration:.25,stagger:.02,ease:`power2.out`});return()=>{t.kill()}}},[l]);let be=e=>String(e.id||e.entity_id),Q=H.entity_types||{},xe=(0,S.useMemo)(()=>[{label:`实体总数`,value:Number(H.node_count||H.total_entities||l.length),color:w},{label:`IP`,value:Number(Q.ip||l.filter(e=>String(e.type)===`ip`).length),color:T},{label:`账号`,value:Number(Q.account||l.filter(e=>String(e.type)===`account`).length),color:le},{label:`黑话`,value:Number(Q.blacktalk||l.filter(e=>String(e.type)===`blacktalk`).length),color:E}],[H,l]),Se=(0,S.useMemo)(()=>{let e={};return l.forEach(t=>{let n=String(t.type||`other`);e[n]=(e[n]||0)+1}),e},[l]),$=(0,S.useMemo)(()=>{let e={};return l.forEach(t=>{let n=String(t.type||`other`);e[n]=(e[n]||0)+1}),Object.entries(e).map(([e,t])=>({name:R.find(t=>t.value===e)?.label||e,value:t}))},[l]),Ce=(0,S.useMemo)(()=>{let e=l.map(e=>{let t=Number(e.mention_count||0);if(t>0)return t;let n=e.source_ids;return n?n.length:0});return Math.max(...e,1)},[l]),we=async()=>{try{let t=await q.validateFields();await b.addEntity(String(t.type),String(t.name||t.value),String(t.description||``),.8),e.success(`实体已添加`),U(!1),q.resetFields(),Z()}catch(t){if(t&&typeof t==`object`&&`errorFields`in t)return;e.error(x(t))}},Te=async()=>{if(K)try{let t=await J.validateFields(),n=be(K);await b.addRelation(n,String(t.target_id),String(t.relationship_type),.8,String(t.description||``)),e.success(`关联已创建`),G(!1),J.resetFields()}catch(t){if(t&&typeof t==`object`&&`errorFields`in t)return;e.error(x(t))}},Ee=async t=>{_e(t);try{await b.deleteEntity(t),e.success(`实体已删除`),Z()}catch(t){e.error(x(t))}finally{_e(null)}},De={background:`#1C1F35`,border:`1px solid ${j}`,borderRadius:8,fontSize:12,color:D,padding:`8px 12px`,...I,boxShadow:`0 2px 8px rgba(0,0,0,0.3)`},Oe=R.filter(e=>Se[e.value]);return(0,C.jsxs)(`div`,{style:{padding:0,background:de,minHeight:`100vh`,overflowX:`hidden`},children:[(0,C.jsx)(`style`,{children:`
        .entity-card {
          transition: transform 0.2s cubic-bezier(0.4,0,0.2,1), box-shadow 0.2s cubic-bezier(0.4,0,0.2,1);
        }
        .entity-card:hover {
          transform: translateY(-4px);
          box-shadow: 0 12px 32px rgba(0,0,0,0.3), 0 2px 8px rgba(0,0,0,0.2);
        }
        .entity-card .card-actions {
          opacity: 0;
          transition: opacity 0.15s ease;
        }
        .entity-card:hover .card-actions {
          opacity: 1;
        }
        .entity-filter-pill {
          transition: all 0.18s cubic-bezier(0.4,0,0.2,1);
          cursor: pointer;
          user-select: none;
        }
        .entity-filter-pill:hover {
          transform: translateY(-1px);
          box-shadow: 0 2px 8px rgba(0,0,0,0.25);
        }
        .entity-filter-pill:active {
          transform: translateY(0);
        }
        .entity-search-input .ant-input {
          border-radius: 20px !important;
          background: ${N} !important;
          font-family: ${F} !important;
          font-size: 13px !important;
          color: ${D} !important;
          height: 36px !important;
        }
        .entity-search-input .ant-input::placeholder {
          color: ${A} !important;
        }
        .entity-search-input .ant-input-affix-wrapper {
          border-radius: 20px !important;
          background: ${N} !important;
          border: 1.5px solid ${j} !important;
          height: 40px !important;
          padding: 0 16px !important;
        }
        .entity-search-input .ant-input-affix-wrapper:hover {
          border-color: ${w} !important;
        }
        .entity-search-input .ant-input-affix-wrapper:focus-within {
          border-color: ${w} !important;
          box-shadow: 0 0 0 3px rgba(108,92,231,0.1) !important;
        }
        .entity-search-input .ant-input-affix-wrapper .ant-input {
          background: transparent !important;
          color: ${D} !important;
        }
        .entity-search-input .ant-input-prefix {
          margin-right: 8px !important;
          color: ${A} !important;
        }
        .entity-modal .ant-modal-content {
          border-radius: 16px !important;
          padding: 0 !important;
          overflow: hidden;
          background: ${N} !important;
          border: 1px solid ${j} !important;
          box-shadow: 0 20px 60px rgba(0,0,0,0.4) !important;
        }
        .entity-modal .ant-modal-header {
          border-radius: 16px 16px 0 0 !important;
          border-bottom: 1px solid ${M} !important;
          padding: 20px 24px !important;
          margin: 0 !important;
          background: #1C1F35 !important;
        }
        .entity-modal .ant-modal-title {
          font-family: ${P} !important;
          font-size: 18px !important;
          font-weight: 700 !important;
          color: ${D} !important;
        }
        .entity-modal .ant-modal-body {
          padding: 24px !important;
          background: ${N} !important;
        }
        .entity-modal .ant-modal-footer {
          border-top: 1px solid ${M} !important;
          padding: 16px 24px !important;
          margin: 0 !important;
          background: #1C1F35 !important;
        }
        .entity-modal .ant-btn {
          border-radius: 10px !important;
          font-family: ${F} !important;
          font-size: 13px !important;
          font-weight: 600 !important;
          height: 38px !important;
          padding: 0 22px !important;
          background: ${N} !important;
          border-color: ${j} !important;
          color: ${D} !important;
        }
        .entity-modal .ant-btn:hover {
          border-color: ${w} !important;
          color: ${w} !important;
        }
        .entity-modal .ant-btn-primary {
          background: ${w} !important;
          border-color: ${w} !important;
          color: #E8E9ED !important;
          font-weight: 700 !important;
        }
        .entity-modal .ant-btn-primary:hover {
          background: #5B4BD5 !important;
          border-color: #5B4BD5 !important;
        }
        .entity-modal .ant-form-item-label > label {
          font-family: ${F} !important;
          font-size: 13px !important;
          color: ${k} !important;
          font-weight: 500 !important;
        }
        .entity-modal .ant-input,
        .entity-modal .ant-select-selector,
        .entity-modal .ant-input-affix-wrapper {
          border-radius: 10px !important;
          background: ${N} !important;
          border-color: ${j} !important;
          color: ${D} !important;
        }
        .entity-modal .ant-input::placeholder {
          color: ${A} !important;
        }
        .entity-modal .ant-input:hover,
        .entity-modal .ant-select-selector:hover,
        .entity-modal .ant-input-affix-wrapper:hover {
          border-color: ${w} !important;
        }
        .entity-modal .ant-input:focus,
        .entity-modal .ant-input-focused,
        .entity-modal .ant-select-selector:focus,
        .entity-modal .ant-input-affix-wrapper:focus {
          border-color: ${w} !important;
          box-shadow: 0 0 0 2px rgba(108,92,231,0.1) !important;
        }
        .entity-modal .ant-select-selection-item {
          color: ${D} !important;
        }
        .entity-modal .ant-select-arrow {
          color: ${k} !important;
        }
        .entity-modal .ant-input-textarea textarea {
          background: ${N} !important;
          color: ${D} !important;
          border-color: ${j} !important;
          border-radius: 10px !important;
        }
        .entity-modal .ant-input-textarea textarea::placeholder {
          color: ${A} !important;
        }
        .entity-modal .ant-input-textarea textarea:hover {
          border-color: ${w} !important;
        }
        .entity-modal .ant-input-textarea textarea:focus {
          border-color: ${w} !important;
          box-shadow: 0 0 0 2px rgba(108,92,231,0.1) !important;
        }
        .entity-pagination .ant-pagination-item {
          border-radius: 8px !important;
          font-family: ${F} !important;
          font-size: 13px !important;
          background: ${N} !important;
          border-color: ${j} !important;
        }
        .entity-pagination .ant-pagination-item a {
          color: ${D} !important;
        }
        .entity-pagination .ant-pagination-item:hover {
          border-color: ${w} !important;
        }
        .entity-pagination .ant-pagination-item:hover a {
          color: ${w} !important;
        }
        .entity-pagination .ant-pagination-item-active {
          background: ${w} !important;
          border-color: ${w} !important;
        }
        .entity-pagination .ant-pagination-item-active a {
          color: #E8E9ED !important;
          font-weight: 700 !important;
        }
        .entity-pagination .ant-pagination-prev .ant-pagination-item-link,
        .entity-pagination .ant-pagination-next .ant-pagination-item-link {
          border-radius: 8px !important;
          background: ${N} !important;
          border-color: ${j} !important;
          color: ${D} !important;
        }
        .entity-pagination .ant-pagination-prev .ant-pagination-item-link:hover,
        .entity-pagination .ant-pagination-next .ant-pagination-item-link:hover {
          border-color: ${w} !important;
          color: ${w} !important;
        }
        .entity-pagination .ant-pagination-disabled .ant-pagination-item-link {
          opacity: 0.4 !important;
        }
        .ant-select-dropdown {
          background: ${N} !important;
          border: 1px solid ${j} !important;
        }
        .ant-select-dropdown .ant-select-item {
          color: ${D} !important;
        }
        .ant-select-dropdown .ant-select-item-option-active {
          background: rgba(255,255,255,0.06) !important;
        }
        .ant-select-dropdown .ant-select-item-option-selected {
          background: rgba(108,92,231,0.08) !important;
          color: ${w} !important;
        }
        .ant-popover-inner {
          background: ${N} !important;
          border: 1px solid ${j} !important;
        }
        .ant-popconfirm-description {
          color: ${D} !important;
        }
        .ant-popconfirm-buttons .ant-btn {
          background: ${N} !important;
          border-color: ${j} !important;
          color: ${D} !important;
        }
        .ant-popconfirm-buttons .ant-btn-primary {
          background: #EF4444 !important;
          border-color: #EF4444 !important;
          color: #fff !important;
        }
      `}),(0,C.jsx)(`div`,{ref:Y,style:{padding:`32px 40px 28px`,background:N,borderBottom:`1px solid ${M}`,boxShadow:`0 4px 16px rgba(0,0,0,0.25)`},children:(0,C.jsxs)(`div`,{style:{display:`flex`,alignItems:`center`,justifyContent:`space-between`},children:[(0,C.jsxs)(`div`,{style:{display:`flex`,alignItems:`center`,gap:16},children:[(0,C.jsx)(`div`,{style:{width:4,height:52,borderRadius:2,background:`linear-gradient(180deg, ${w}, ${T})`,flexShrink:0}}),(0,C.jsxs)(`div`,{children:[(0,C.jsx)(`h1`,{style:{fontFamily:P,fontSize:26,fontWeight:800,color:D,margin:0,lineHeight:1.2,letterSpacing:-.5},children:`实体档案`}),(0,C.jsx)(`p`,{style:{fontFamily:F,fontSize:13,color:k,margin:`4px 0 0`,lineHeight:1.4},children:`黑产实体提取与管理`})]})]}),(0,C.jsxs)(`div`,{style:{display:`flex`,alignItems:`center`,gap:10},children:[xe.map(e=>(0,C.jsxs)(`div`,{style:{display:`inline-flex`,alignItems:`center`,gap:8,padding:`8px 16px`,borderRadius:12,background:`${e.color}08`,border:`1px solid ${e.color}15`},children:[(0,C.jsx)(`div`,{style:{width:8,height:8,borderRadius:3,background:e.color,flexShrink:0}}),(0,C.jsxs)(`div`,{style:{display:`flex`,flexDirection:`column`,gap:1},children:[(0,C.jsx)(`span`,{style:{fontFamily:F,fontSize:10,color:A,fontWeight:500,lineHeight:1,textTransform:`uppercase`,letterSpacing:.5},children:e.label}),(0,C.jsx)(`span`,{style:{fontFamily:F,fontSize:18,fontWeight:700,color:e.color,lineHeight:1.2,...I},children:e.value})]})]},e.label)),(0,C.jsx)(`div`,{style:{width:1,height:36,background:j,margin:`0 4px`}}),(0,C.jsx)(f,{onClick:Z,icon:(0,C.jsx)(u,{}),"aria-label":`刷新数据`,style:{borderRadius:10,fontFamily:F,fontWeight:600,height:38,fontSize:13,color:k,border:`1px solid ${j}`},children:`刷新`}),(0,C.jsx)(f,{type:`primary`,icon:(0,C.jsx)(d,{}),onClick:()=>U(!0),"aria-label":`添加实体`,style:{borderRadius:10,fontFamily:F,fontWeight:700,height:38,fontSize:13,background:`linear-gradient(135deg, ${w}, #5B4BD5)`,borderColor:w,boxShadow:`0 2px 8px ${w}30`},children:`添加实体`})]})]})}),(0,C.jsx)(`div`,{style:{padding:`20px 40px`},children:(0,C.jsxs)(`div`,{style:{background:N,borderRadius:12,border:`1px solid ${j}`,boxShadow:`0 4px 16px rgba(0,0,0,0.25)`,padding:`14px 20px`,display:`flex`,alignItems:`center`,gap:16},children:[(0,C.jsxs)(`div`,{style:{display:`flex`,alignItems:`center`,gap:6,flexWrap:`wrap`,flex:1},children:[(0,C.jsxs)(`div`,{className:`entity-filter-pill`,onClick:()=>V(void 0),style:{display:`inline-flex`,alignItems:`center`,gap:6,padding:`7px 16px`,borderRadius:20,background:B?`rgba(255,255,255,0.06)`:w,color:B?O:`#E8E9ED`,border:`1.5px solid ${B?`transparent`:w}`,fontFamily:F,fontSize:13,fontWeight:B?500:700,whiteSpace:`nowrap`},children:[(0,C.jsx)(h,{style:{fontSize:12}}),`全部`,(0,C.jsx)(`span`,{style:{...I,fontSize:11,fontWeight:700,background:B?`${k}20`:`rgba(255,255,255,0.25)`,color:B?k:`rgba(255,255,255,0.9)`,padding:`1px 8px`,borderRadius:10,marginLeft:2},children:l.length})]}),Oe.map(e=>{let t=B===e.value,n=Se[e.value]||0;return(0,C.jsxs)(`div`,{className:`entity-filter-pill`,onClick:()=>V(t?void 0:e.value),style:{display:`inline-flex`,alignItems:`center`,gap:6,padding:`7px 16px`,borderRadius:20,background:t?e.color:`rgba(255,255,255,0.06)`,color:t?`#E8E9ED`:O,border:`1.5px solid ${t?e.color:`transparent`}`,fontFamily:F,fontSize:13,fontWeight:t?700:500,whiteSpace:`nowrap`},children:[e.icon&&(0,C.jsx)(`span`,{style:{fontSize:12,display:`inline-flex`,alignItems:`center`},children:e.icon}),e.label,(0,C.jsx)(`span`,{style:{...I,fontSize:11,fontWeight:700,background:t?`rgba(255,255,255,0.25)`:`${e.color}15`,color:t?`rgba(255,255,255,0.9)`:e.color,padding:`1px 8px`,borderRadius:10,marginLeft:2},children:n})]},e.value)})]}),(0,C.jsx)(s,{className:`entity-search-input`,placeholder:`搜索实体...`,value:v,onChange:e=>z(e.target.value),allowClear:!0,style:{width:240,flexShrink:0},prefix:(0,C.jsx)(ie,{style:{fontSize:14}})})]})}),$.length>0&&(0,C.jsx)(`div`,{style:{padding:`0 40px 20px`},children:(0,C.jsxs)(`div`,{style:{background:N,borderRadius:12,border:`1px solid ${j}`,overflow:`hidden`,boxShadow:`0 4px 16px rgba(0,0,0,0.25)`},children:[(0,C.jsx)(`div`,{style:{height:3,background:`linear-gradient(90deg, ${w}, ${T}, ${le}, ${E}, ${ue})`}}),(0,C.jsxs)(`div`,{style:{padding:`16px 20px`,borderBottom:`1px solid ${M}`,display:`flex`,alignItems:`center`,justifyContent:`space-between`},children:[(0,C.jsxs)(`div`,{style:{display:`flex`,alignItems:`center`,gap:10},children:[(0,C.jsx)(`div`,{style:{width:28,height:28,borderRadius:8,background:`${w}10`,display:`flex`,alignItems:`center`,justifyContent:`center`},children:(0,C.jsx)(h,{style:{fontSize:14,color:w}})}),(0,C.jsx)(`span`,{style:{fontFamily:P,fontSize:16,fontWeight:700,color:D},children:`实体类型分布`})]}),(0,C.jsx)(`div`,{style:{display:`flex`,flexWrap:`wrap`,gap:14},children:$.map((e,t)=>(0,C.jsxs)(`div`,{style:{display:`flex`,alignItems:`center`,gap:6},children:[(0,C.jsx)(`div`,{style:{width:8,height:8,borderRadius:3,background:L[t%L.length]}}),(0,C.jsx)(`span`,{style:{color:k,fontSize:12,fontFamily:F,fontWeight:500},children:e.name}),(0,C.jsx)(`span`,{style:{color:D,fontSize:12,...I,fontWeight:600},children:e.value})]},e.name))})]}),(0,C.jsx)(`div`,{style:{padding:`8px 0 0`},children:(0,C.jsx)(oe,{width:`100%`,height:200,children:(0,C.jsx)(se,{data:$,dataKey:`value`,nameKey:`name`,stroke:`#141625`,fill:w,aspectRatio:4/3,content:(0,C.jsx)(fe,{}),children:(0,C.jsx)(ce,{contentStyle:De,formatter:(e,t)=>[e,t]})})})})]})}),(0,C.jsx)(`div`,{style:{padding:`0 40px 32px`},children:g?(0,C.jsx)(`div`,{style:{display:`flex`,justifyContent:`center`,padding:64},children:(0,C.jsx)(ne,{})}):l.length===0?(0,C.jsx)(`div`,{style:{padding:`80px 0`,textAlign:`center`,background:N,borderRadius:12,border:`1px solid ${j}`,boxShadow:`0 4px 16px rgba(0,0,0,0.25)`},children:(0,C.jsx)(re,{description:(0,C.jsx)(`span`,{style:{color:k,fontFamily:F,fontSize:13},children:`暂无实体，点击「添加实体」开始管理`}),children:(0,C.jsx)(f,{type:`primary`,icon:(0,C.jsx)(d,{}),onClick:()=>U(!0),style:{borderRadius:10,fontFamily:F,fontWeight:700,height:38,background:w,borderColor:w},children:`添加实体`})})}):(0,C.jsxs)(C.Fragment,{children:[(0,C.jsxs)(`div`,{style:{display:`flex`,alignItems:`center`,justifyContent:`space-between`,marginBottom:18},children:[(0,C.jsxs)(`div`,{style:{display:`flex`,alignItems:`center`,gap:10},children:[(0,C.jsx)(`div`,{style:{width:28,height:28,borderRadius:8,background:`${w}10`,display:`flex`,alignItems:`center`,justifyContent:`center`},children:(0,C.jsx)(h,{style:{fontSize:14,color:w}})}),(0,C.jsx)(`span`,{style:{fontFamily:P,fontSize:16,fontWeight:700,color:D},children:`实体列表`})]}),(0,C.jsxs)(`span`,{style:{...I,fontSize:13,color:A,fontFamily:F},children:[l.length,` 条记录`]})]}),(0,C.jsx)(`div`,{ref:X,style:{display:`grid`,gridTemplateColumns:`repeat(auto-fill, minmax(340px, 1fr))`,gap:16},children:l.slice((W-1)*12,W*12).map(e=>{let i=String(e.type||`other`),a=R.find(e=>e.value===i),o=a?.color||`#7C7F9A`,s=a?.label||i,c=be(e),l=Number(e.mention_count||0),u=l>0?l:e.source_ids?.length||0,d=Math.min(u/Ce*100,100),p=String(e.context||e.description||``);return(0,C.jsxs)(`div`,{className:`entity-card`,style:{background:N,borderRadius:12,border:`1px solid ${j}`,borderTop:`3px solid ${o}`,overflow:`hidden`,cursor:`default`,position:`relative`,display:`flex`,flexDirection:`column`,boxShadow:`0 4px 16px rgba(0,0,0,0.25)`},children:[(0,C.jsxs)(`div`,{style:{padding:`16px 18px 0`},children:[(0,C.jsxs)(`div`,{style:{display:`flex`,justifyContent:`space-between`,alignItems:`flex-start`},children:[(0,C.jsx)(`div`,{style:{flex:1,minWidth:0},children:(0,C.jsx)(`div`,{style:{fontFamily:F,fontSize:16,fontWeight:700,color:D,overflow:`hidden`,textOverflow:`ellipsis`,whiteSpace:`nowrap`,lineHeight:1.4},children:String(e.name||e.value||`—`)})}),(0,C.jsxs)(ee,{size:2,className:`card-actions`,style:{flexShrink:0,marginLeft:8},children:[(0,C.jsx)(t,{title:`关联`,children:(0,C.jsx)(f,{type:`text`,size:`small`,icon:(0,C.jsx)(n,{}),onClick:()=>{ye(e),G(!0)},style:{color:k,fontSize:13,borderRadius:8,width:30,height:30,display:`flex`,alignItems:`center`,justifyContent:`center`}})}),(0,C.jsx)(r,{title:`确认删除？`,onConfirm:()=>Ee(c),okText:`删除`,cancelText:`取消`,okButtonProps:{danger:!0},children:(0,C.jsx)(t,{title:`删除`,children:(0,C.jsx)(f,{type:`text`,size:`small`,icon:(0,C.jsx)(te,{}),danger:!0,loading:ge===c,style:{fontSize:13,borderRadius:8,width:30,height:30,display:`flex`,alignItems:`center`,justifyContent:`center`}})})})]})]}),(0,C.jsx)(`div`,{style:{marginTop:8,display:`flex`,alignItems:`center`,gap:8},children:(0,C.jsxs)(`span`,{style:{display:`inline-flex`,alignItems:`center`,gap:4,padding:`3px 10px`,borderRadius:6,background:`${o}10`,color:o,fontFamily:F,fontSize:11,fontWeight:600},children:[a?.icon&&(0,C.jsx)(`span`,{style:{fontSize:10,display:`inline-flex`,alignItems:`center`},children:a.icon}),s]})})]}),(0,C.jsx)(`div`,{style:{padding:`8px 18px 0`},children:(0,C.jsx)(`div`,{style:{fontFamily:F,fontSize:13,color:p?k:A,overflow:`hidden`,textOverflow:`ellipsis`,whiteSpace:`nowrap`,lineHeight:1.5,fontStyle:p?`normal`:`italic`},children:p||`暂无描述`})}),(0,C.jsxs)(`div`,{style:{margin:`12px 18px 0`,padding:`10px 0 14px`,borderTop:`1px solid ${M}`},children:[(0,C.jsxs)(`div`,{style:{display:`flex`,alignItems:`center`,justifyContent:`space-between`,marginBottom:6},children:[(0,C.jsx)(`span`,{style:{fontSize:11,color:A,fontFamily:F,fontWeight:500,letterSpacing:.3},children:`提及次数`}),(0,C.jsx)(`span`,{style:{fontSize:14,fontWeight:700,color:o,...I},children:u})]}),(0,C.jsx)(`div`,{style:{height:4,borderRadius:2,background:M,overflow:`hidden`},children:(0,C.jsx)(`div`,{style:{height:`100%`,borderRadius:2,background:`linear-gradient(90deg, ${o}, ${o}BB)`,width:`${d}%`,transition:`width 0.3s ease`}})})]})]},c)})}),l.length>12&&(0,C.jsx)(`div`,{className:`entity-pagination`,style:{display:`flex`,justifyContent:`flex-end`,marginTop:24},children:(0,C.jsx)(a,{current:W,pageSize:12,total:l.length,onChange:he,size:`small`,showTotal:e=>`共 ${e} 条`})})]})}),(0,C.jsx)(o,{className:`entity-modal`,open:me,onCancel:()=>{U(!1),q.resetFields()},onOk:we,width:520,okText:`添加`,cancelText:`取消`,title:`添加实体`,styles:{content:{borderRadius:16},mask:{borderRadius:16}},children:(0,C.jsxs)(c,{form:q,layout:`vertical`,style:{marginTop:16},children:[(0,C.jsx)(c.Item,{name:`name`,label:`实体名称`,rules:[{required:!0,message:`请输入实体名称`}],children:(0,C.jsx)(s,{placeholder:`例如: 料卡、洗钱通道`,style:{borderRadius:10}})}),(0,C.jsx)(c.Item,{name:`type`,label:`实体类型`,rules:[{required:!0,message:`请选择类型`}],children:(0,C.jsx)(p,{options:R.map(e=>({value:e.value,label:e.label})),placeholder:`选择类型`})}),(0,C.jsx)(c.Item,{name:`value`,label:`实体值`,children:(0,C.jsx)(s,{placeholder:`实体的具体值，如URL、账号等`,style:{borderRadius:10}})}),(0,C.jsx)(c.Item,{name:`source`,label:`来源`,children:(0,C.jsx)(s,{placeholder:`情报来源`,style:{borderRadius:10}})}),(0,C.jsx)(c.Item,{name:`description`,label:`描述`,children:(0,C.jsx)(s.TextArea,{rows:3,placeholder:`实体描述信息`,style:{borderRadius:10}})})]})}),(0,C.jsx)(o,{className:`entity-modal`,open:ve,onCancel:()=>{G(!1),J.resetFields()},onOk:Te,width:480,okText:`创建关联`,cancelText:`取消`,title:`创建关联`,styles:{content:{borderRadius:16},mask:{borderRadius:16}},children:(0,C.jsxs)(`div`,{style:{marginTop:16},children:[K&&(0,C.jsxs)(`div`,{style:{padding:14,background:`#1C1F35`,borderRadius:10,border:`1px solid ${M}`,marginBottom:16},children:[(0,C.jsx)(`span`,{style:{fontSize:12,fontFamily:F,color:A},children:`当前实体 `}),(0,C.jsx)(`span`,{style:{fontWeight:600,fontFamily:F,fontSize:13,color:w},children:String(K.name||K.value||`—`)})]}),(0,C.jsxs)(c,{form:J,layout:`vertical`,children:[(0,C.jsx)(c.Item,{name:`target_id`,label:`目标实体ID`,rules:[{required:!0,message:`请输入目标实体ID`}],children:(0,C.jsx)(s,{placeholder:`输入要关联的实体ID`,style:{borderRadius:10}})}),(0,C.jsx)(c.Item,{name:`relationship_type`,label:`关系类型`,rules:[{required:!0,message:`请选择关系类型`}],children:(0,C.jsx)(p,{options:[{value:`related_to`,label:`相关`},{value:`uses`,label:`使用`},{value:`belongs_to`,label:`属于`},{value:`communicates_with`,label:`通信`},{value:`located_in`,label:`位于`}],placeholder:`选择关系类型`})}),(0,C.jsx)(c.Item,{name:`description`,label:`关系描述`,children:(0,C.jsx)(s.TextArea,{rows:2,placeholder:`描述两个实体之间的关系`,style:{borderRadius:10}})})]})]})})]})};export{z as default};