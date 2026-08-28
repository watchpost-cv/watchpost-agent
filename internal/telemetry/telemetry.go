package telemetry

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/watchpost-ops/watchpost-agent/internal/state"
)

type Sample struct { Sequence int64 `json:"sequence"`; ObservedAt time.Time `json:"observed_at"`; Signal string `json:"signal"`; Value *float64 `json:"value"`; Unit string `json:"unit"`; Quality string `json:"quality"`; Labels map[string]string `json:"labels"` }
type Batch struct { Version int `json:"version"`; PostID string `json:"post_id"`; CollectorID string `json:"collector_id"`; BatchID string `json:"batch_id"`; SentAt time.Time `json:"sent_at"`; Samples []Sample `json:"samples"` }

func Send(ctx context.Context, store *state.Store) error {
	current:=store.Snapshot();if current.Connection.Credential==""{return errors.New("agent is not paired")};now:=time.Now().UTC();values,err:=snapshot();if err!=nil{return err};sequence:=current.NextSequence;if sequence<1{sequence=1};samples:=make([]Sample,0,len(values));for _,value:=range values{copy:=value.value;samples=append(samples,Sample{Sequence:sequence,ObservedAt:now,Signal:value.signal,Value:&copy,Unit:value.unit,Quality:"good",Labels:map[string]string{}});sequence++}
	batch:=Batch{Version:1,PostID:current.Connection.PostID,CollectorID:current.InstallationID,BatchID:fmt.Sprintf("agent-%d",now.UnixNano()),SentAt:now,Samples:samples};body,_:=json.Marshal(batch);request,err:=http.NewRequestWithContext(ctx,http.MethodPost,strings.TrimRight(current.Connection.WatchpostURL,"/")+"/api/collector/v1/observations",bytes.NewReader(body));if err!=nil{return err};request.Header.Set("Content-Type","application/json");request.Header.Set("Authorization","Bearer "+current.Connection.Credential);response,err:=(&http.Client{Timeout:10*time.Second}).Do(request);if err!=nil{return err};defer response.Body.Close();if response.StatusCode!=http.StatusAccepted{return fmt.Errorf("telemetry rejected (%d)",response.StatusCode)};return store.Update(func(value *state.State)error{value.NextSequence=sequence;return nil})
}

type metric struct{signal,unit string;value float64}
func snapshot()([]metric,error){cpu,err:=cpuPercent();if err!=nil{return nil,err};memory,err:=memoryPercent();if err!=nil{return nil,err};var disk syscall.Statfs_t;if err=syscall.Statfs("/",&disk);err!=nil{return nil,err};diskPercent:=0.0;if disk.Blocks>0{diskPercent=100*float64(disk.Blocks-disk.Bfree)/float64(disk.Blocks)};uptime,err:=os.ReadFile("/proc/uptime");if err!=nil{return nil,err};seconds,_:=strconv.ParseFloat(strings.Fields(string(uptime))[0],64);return []metric{{"cpu.percent","percent",cpu},{"memory.percent","percent",memory},{"disk.percent","percent",diskPercent},{"uptime.seconds","seconds",seconds}},nil}
func cpuPercent()(float64,error){idle1,total1,err:=cpuTimes();if err!=nil{return 0,err};time.Sleep(100*time.Millisecond);idle2,total2,err:=cpuTimes();if err!=nil{return 0,err};delta:=total2-total1;if delta==0{return 0,nil};return 100*(1-float64(idle2-idle1)/float64(delta)),nil}
func cpuTimes()(uint64,uint64,error){file,err:=os.Open("/proc/stat");if err!=nil{return 0,0,err};defer file.Close();scanner:=bufio.NewScanner(file);if !scanner.Scan(){return 0,0,errors.New("cpu telemetry unavailable")};fields:=strings.Fields(scanner.Text());if len(fields)<5||fields[0]!="cpu"{return 0,0,errors.New("invalid cpu telemetry")};var total,idle uint64;for index,text:=range fields[1:]{value,parseErr:=strconv.ParseUint(text,10,64);if parseErr!=nil{return 0,0,parseErr};total+=value;if index==3||index==4{idle+=value}};return idle,total,nil}
func memoryPercent()(float64,error){data,err:=os.ReadFile("/proc/meminfo");if err!=nil{return 0,err};values:=map[string]float64{};scanner:=bufio.NewScanner(bytes.NewReader(data));for scanner.Scan(){fields:=strings.Fields(scanner.Text());if len(fields)>=2{values[strings.TrimSuffix(fields[0],":")],_=strconv.ParseFloat(fields[1],64)}};total:=values["MemTotal"];if total<=0{return 0,errors.New("invalid memory telemetry")};available:=values["MemAvailable"];return 100*(total-available)/total,nil}
