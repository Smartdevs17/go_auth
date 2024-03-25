package initializers

import "github.com/Smartdevs17/go_auth/models"

func SyncDatabase() {
	DB.AutoMigrate(&models.User{})

}
