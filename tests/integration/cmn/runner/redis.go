package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime/debug"
	"strconv"
	"sync"
	"time"

	docker "github.com/fsouza/go-dockerclient"
	"github.com/go-redis/redis/v8"
	runnerFbk "github.com/hyperledger/fabric/integration/nwo/runner"
	"github.com/tedsuo/ifrit"
)

const (
	RedisDefaultImage = "redis:7.2.4"
)

// RedisDB manages the execution of an instance of a dockerized RedisDB for tests.
type RedisDB struct {
	Client        *docker.Client
	Image         string
	HostIP        string
	HostPort      int
	ContainerPort docker.Port
	Name          string
	StartTimeout  time.Duration
	Binds         []string

	ErrorStream  io.Writer
	OutputStream io.Writer

	creator          string
	containerID      string
	hostAddress      string
	containerAddress string
	address          string

	mutex   sync.Mutex
	stopped bool
}

// Run runs a RedisDB container. It implements the ifrit.Runner interface
func (r *RedisDB) Run(sigCh <-chan os.Signal, ready chan<- struct{}) error {
	if r.Image == "" {
		r.Image = RedisDefaultImage
	}

	if r.Name == "" {
		r.Name = runnerFbk.DefaultNamer()
	}

	if r.HostIP == "" {
		r.HostIP = "127.0.0.1"
	}

	if r.ContainerPort == ("") {
		r.ContainerPort = "6379/tcp"
	}

	if r.StartTimeout == 0 {
		r.StartTimeout = runnerFbk.DefaultStartTimeout
	}

	if r.Client == nil {
		client, err := docker.NewClientFromEnv()
		if err != nil {
			return err
		}
		r.Client = client
	}

	hostConfig := &docker.HostConfig{
		AutoRemove: true,
		PortBindings: map[docker.Port][]docker.PortBinding{
			r.ContainerPort: {{
				HostIP:   r.HostIP,
				HostPort: strconv.Itoa(r.HostPort),
			}},
		},
		Binds: r.Binds,
	}

	container, err := r.Client.CreateContainer(
		docker.CreateContainerOptions{
			Name: r.Name,
			Config: &docker.Config{
				Image: r.Image,
			},
			HostConfig: hostConfig,
		},
	)
	if err != nil {
		return err
	}
	r.containerID = container.ID

	err = r.Client.StartContainer(container.ID, nil)
	if err != nil {
		return err
	}
	defer func() { err = r.Stop() }()

	container, err = r.Client.InspectContainerWithOptions(docker.InspectContainerOptions{ID: container.ID})
	if err != nil {
		return err
	}
	r.hostAddress = net.JoinHostPort(
		container.NetworkSettings.Ports[r.ContainerPort][0].HostIP,
		container.NetworkSettings.Ports[r.ContainerPort][0].HostPort,
	)
	r.containerAddress = net.JoinHostPort(
		container.NetworkSettings.IPAddress,
		r.ContainerPort.Port(),
	)

	streamCtx, streamCancel := context.WithCancel(context.Background())
	defer streamCancel()
	go r.streamLogs(streamCtx)

	containerExit := r.wait()
	ctx, cancel := context.WithTimeout(context.Background(), r.StartTimeout)
	defer cancel()

	select {
	case <-ctx.Done():
		return fmt.Errorf("database in container %s did not start: %w", r.containerID, ctx.Err())
	case <-containerExit:
		return errors.New("container exited before ready")
	case <-r.ready(ctx, r.hostAddress):
		r.address = r.hostAddress
	case <-r.ready(ctx, r.containerAddress):
		r.address = r.containerAddress
	}

	cancel()
	close(ready)

	for {
		select {
		case err := <-containerExit:
			return err
		case <-sigCh:
			if err := r.Stop(); err != nil {
				return err
			}
		}
	}
}

func endpointReady(ctx context.Context, addr string) bool {
	ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	redisOpts := &redis.UniversalOptions{
		Addrs:    []string{addr},
		Password: "",
		ReadOnly: false,
	}
	client := redis.NewUniversalClient(redisOpts)

	status := client.Ping(ctx)
	if status.Err() != nil {
		return false
	}

	if status.Val() != "PONG" {
		return false
	}

	return true
}

func (r *RedisDB) ready(ctx context.Context, addr string) <-chan struct{} {
	readyCh := make(chan struct{})
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			if endpointReady(ctx, addr) {
				close(readyCh)
				return
			}
			select {
			case <-ticker.C:
			case <-ctx.Done():
				return
			}
		}
	}()

	return readyCh
}

func (r *RedisDB) wait() <-chan error {
	exitCh := make(chan error)
	go func() {
		exitCode, err := r.Client.WaitContainer(r.containerID)
		if err == nil {
			err = fmt.Errorf("redisdb: process exited with %d", exitCode)
		}
		exitCh <- err
	}()

	return exitCh
}

func (r *RedisDB) streamLogs(ctx context.Context) {
	if r.ErrorStream == nil && r.OutputStream == nil {
		return
	}

	logOptions := docker.LogsOptions{
		Context:      ctx,
		Container:    r.containerID,
		Follow:       true,
		ErrorStream:  r.ErrorStream,
		OutputStream: r.OutputStream,
		Stderr:       r.ErrorStream != nil,
		Stdout:       r.OutputStream != nil,
	}

	err := r.Client.Logs(logOptions)
	if err != nil {
		fmt.Fprintf(r.ErrorStream, "log stream ended with error: %s", err)
	}
}

// Address returns the address successfully used by the readiness check.
func (r *RedisDB) Address() string {
	return r.address
}

// HostAddress returns the host address where this RedisDB instance is available.
func (r *RedisDB) HostAddress() string {
	return r.hostAddress
}

// ContainerAddress returns the container address where this RedisDB instance
// is available.
func (r *RedisDB) ContainerAddress() string {
	return r.containerAddress
}

// ContainerID returns the container ID of this RedisDB
func (r *RedisDB) ContainerID() string {
	return r.containerID
}

// Start starts the RedisDB container using an ifrit runner
func (r *RedisDB) Start() error {
	r.creator = string(debug.Stack())
	p := ifrit.Invoke(r)

	select {
	case <-p.Ready():
		return nil
	case err := <-p.Wait():
		return err
	}
}

// Stop stops and removes the RedisDB container
func (r *RedisDB) Stop() error {
	r.mutex.Lock()
	if r.stopped {
		r.mutex.Unlock()
		return errors.New("container " + r.containerID + " already stopped")
	}
	r.stopped = true
	r.mutex.Unlock()

	err := r.Client.StopContainer(r.containerID, 0)
	if err != nil {
		return err
	}

	return nil
}
