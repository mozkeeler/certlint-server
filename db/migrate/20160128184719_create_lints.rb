class CreateLints < ActiveRecord::Migration
  def change
    create_table :lints do |t|
      t.string :host
      t.text :root

      t.timestamps null: false
    end
  end
end
