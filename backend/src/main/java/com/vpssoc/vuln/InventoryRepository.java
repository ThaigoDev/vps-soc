package com.vpssoc.vuln;

import org.springframework.data.jpa.repository.JpaRepository;

public interface InventoryRepository extends JpaRepository<ServiceInventory, ServiceInventory.Key> {
}
