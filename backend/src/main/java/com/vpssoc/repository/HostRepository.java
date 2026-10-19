package com.vpssoc.repository;

import com.vpssoc.domain.Host;
import com.vpssoc.domain.HostStatus;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface HostRepository extends JpaRepository<Host, String> {

    List<Host> findByStatus(HostStatus status);

    List<Host> findAllByOrderByIdAsc();
}
